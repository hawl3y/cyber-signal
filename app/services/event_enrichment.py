import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

import requests
from flask import current_app

from app.extensions import db
from app.models import CyberEvent, EnrichmentAuditLog, EventSourceLink, RawArticle
from app.services.ai_enrichment import (
    ALLOWED_ATTACK_TYPES,
    ALLOWED_ATTRIBUTION_STATUS,
    ALLOWED_ACTOR_TYPES,
    ALLOWED_INDUSTRIES,
    _base_xai_config,
    _clean_actor_name,
    _clean_model_text,
    _extract_json_object,
    _extract_output_text_from_responses_api,
    _extract_source_urls_from_responses_api,
    _is_generic_actor_name,
    _is_valid_actor_name,
    _truncate_text,
    _valid_value,
)
from app.services.extraction import region_for_country


MAX_ARTICLES_PER_EVENT_PAYLOAD = 5
ARTICLE_TITLE_LIMIT = 300
ARTICLE_SUMMARY_LIMIT = 800
ARTICLE_CONTENT_LIMIT = 1200


def _is_blank(value):
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    return False


def _is_unknown_or_blank(value):
    if _is_blank(value):
        return True
    return isinstance(value, str) and value.strip().lower() == "unknown"


def _missing_geography(event):
    return _is_blank(event.country) and _is_blank(event.region)


def _has_fillable_blanks(event):
    """
    True when the event has at least one field that AI enrichment could fill,
    respecting data-integrity rules (no actor on activity events, no actor
    without victim).
    """
    if _is_unknown_or_blank(event.industry):
        return True
    if _is_unknown_or_blank(event.attack_type):
        return True
    if _missing_geography(event):
        return True
    if _is_blank(event.summary_short):
        return True

    if event.event_signal_type == "incident":
        if _is_blank(event.victim_org_name):
            return True
        if event.victim_org_name and (
            _is_blank(event.actor_name)
            or _is_generic_actor_name(event.actor_name)
            or _is_blank(event.actor_type)
            or _is_blank(event.attribution_status)
        ):
            return True

    return False


UPDATED_AT_TOLERANCE = timedelta(seconds=2)


def _needs_enrichment(event, force=False):
    if not _has_fillable_blanks(event):
        return False

    if force:
        return True

    if event.last_enriched_at and event.updated_at:
        # SQLAlchemy's onupdate bumps updated_at microseconds after we set
        # last_enriched_at in the same commit. A new article clustering into
        # the event later (cron runs are hours apart) will move updated_at
        # well beyond this tolerance, so this only suppresses our own commit
        # noise, not real new-article signals.
        if event.updated_at <= event.last_enriched_at + UPDATED_AT_TOLERANCE:
            return False

    return True


def _events_needing_enrichment(force=False):
    events = CyberEvent.query.order_by(CyberEvent.updated_at.desc()).all()
    return [event for event in events if _needs_enrichment(event, force=force)]


def _source_articles_for_event(event):
    links = (
        EventSourceLink.query.filter_by(cyber_event_id=event.id)
        .order_by(EventSourceLink.is_primary_source.desc(), EventSourceLink.linked_at.desc())
        .limit(MAX_ARTICLES_PER_EVENT_PAYLOAD)
        .all()
    )

    articles = []
    for link in links:
        article = RawArticle.query.get(link.raw_article_id)
        if article:
            articles.append(article)
    return articles


def _event_current_signals(event):
    return {
        "victim_org_name": event.victim_org_name,
        "industry": event.industry,
        "attack_type": event.attack_type,
        "actor_name": event.actor_name,
        "actor_type": event.actor_type,
        "attribution_status": event.attribution_status,
        "country": event.country,
        "region": event.region,
        "short_event_summary": event.summary_short,
        "event_signal_type": event.event_signal_type,
    }


def _build_article_summaries(articles):
    summaries = []
    for article in articles:
        summaries.append({
            "source_name": article.source_name,
            "publisher": article.publisher,
            "title": _truncate_text(article.title, ARTICLE_TITLE_LIMIT),
            "summary": _truncate_text(article.summary, ARTICLE_SUMMARY_LIMIT),
            "content_excerpt": _truncate_text(article.content, ARTICLE_CONTENT_LIMIT),
        })
    return summaries


def _build_event_payload(event):
    articles = _source_articles_for_event(event)
    return {
        "current_signals": _event_current_signals(event),
        "canonical_title": event.canonical_title,
        "source_articles": _build_article_summaries(articles),
    }


def _return_schema():
    return {
        "victim_org_name": "string or null",
        "industry": "one allowed industry value or null",
        "attack_type": "one allowed attack type value or null",
        "actor_name": "string or null",
        "actor_type": "one allowed actor_type value or null",
        "attribution_status": "one allowed attribution_status value or null",
        "country": "string or null",
        "region": "string or null",
        "short_event_summary": "one sentence or null",
    }


def _allowed_values():
    return {
        "industry": sorted(ALLOWED_INDUSTRIES),
        "attack_type": sorted(ALLOWED_ATTACK_TYPES),
        "actor_type": sorted(ALLOWED_ACTOR_TYPES),
        "attribution_status": sorted(ALLOWED_ATTRIBUTION_STATUS),
    }


def _call_xai_event_article_only(event_payload):
    api_key, base_url, model = _base_xai_config()
    if not api_key:
        return None, {}

    prompt = {
        "task": (
            "Extract structured cyber event fields from the provided source articles. "
            "All articles describe the same incident or activity."
        ),
        "rules": [
            "Use only the supplied article fields and current_signals.",
            "Do not use outside knowledge.",
            "Do not invent victim names, industries, countries, threat actors, or attack types.",
            "Treat current_signals as already-validated facts; only fill fields that are null or 'Unknown'.",
            "When source articles disagree, prefer the value supported by the most articles.",
            "Return null when a field is not supported by the supplied data.",
            "Return JSON only. No markdown.",
        ],
        "actor_extraction_rules": [
            "Extract actor_name only when the supplied articles explicitly name or describe a claimed, suspected, or confirmed actor.",
            "Prefer proper group names over generic phrases.",
            "If a group claimed responsibility, attribution_status is 'claimed'.",
            "If an actor is linked to / suspected / believed / attributed by researchers, attribution_status is 'suspected'.",
            "If officials or the victim or credible researchers confirmed attribution, attribution_status is 'confirmed'.",
            "Hacktivist language → actor_type 'hacktivist' (even if also called state-backed) unless explicitly nation-state.",
            "Only state-sponsored / nation-state language → actor_type 'nation_state'.",
            "Ransomware / extortion / financially motivated / criminal language → actor_type 'cybercriminal'.",
        ],
        "allowed_values": _allowed_values(),
        "event_payload": event_payload,
        "return_schema": _return_schema(),
    }

    response = requests.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You extract structured cyber event fields. Return JSON only. No markdown.",
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt),
                },
            ],
            "temperature": 0,
            "max_tokens": 600,
        },
        timeout=30,
    )

    response.raise_for_status()
    data = response.json()

    output_text = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content")
    )

    return _extract_json_object(output_text), data.get("usage", {}) or {}


def _call_xai_event_web_enrichment(event_payload):
    api_key, base_url, model = _base_xai_config()
    if not api_key:
        return None, [], {}

    prompt = {
        "task": "Enrich a cyber event using web search and return structured JSON.",
        "rules": [
            "Use the supplied event_payload as the starting point.",
            "Use web search to corroborate missing or weak fields only.",
            "Treat current_signals as already-validated facts; only fill fields that are null or 'Unknown'.",
            "Prefer authoritative reporting, official disclosures, victim statements, government advisories, or reputable cyber news sources.",
            "Do not guess. Return null for fields that cannot be corroborated.",
            "Return JSON only. No markdown. No citations inside field values.",
            "Return no more than five source URLs.",
        ],
        "enrichment_targets": [
            "victim_org_name",
            "industry",
            "attack_type",
            "actor_name",
            "actor_type",
            "attribution_status",
            "country",
            "region",
            "short_event_summary",
        ],
        "actor_rules": [
            "Prefer the most specific named threat actor or group.",
            "Do not return generic actor names such as hackers, attackers, threat actors, or ransomware group when a specific group name is available.",
            "Claimed responsibility → 'claimed'.",
            "Suspected / linked / believed / attributed → 'suspected'.",
            "Confirmed by officials or victim or credible researchers → 'confirmed'.",
            "Hacktivist groups → 'hacktivist'.",
            "Financially motivated ransomware/extortion → 'cybercriminal'.",
            "State-sponsored / nation-state → 'nation_state'.",
        ],
        "allowed_values": _allowed_values(),
        "event_payload": event_payload,
        "search_query_hint": "cyberattack victim threat actor claimed responsibility industry attack type",
        "return_schema": _return_schema(),
    }

    response = requests.post(
        f"{base_url}/responses",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "input": json.dumps(prompt),
            "tools": [{"type": "web_search"}],
            "temperature": 0,
            "max_output_tokens": 600,
        },
        timeout=60,
    )

    response.raise_for_status()
    data = response.json()

    output_text = _extract_output_text_from_responses_api(data)
    source_urls = _extract_source_urls_from_responses_api(data)

    return _extract_json_object(output_text), source_urls, data.get("usage", {}) or {}


def _filter_preferred_source_urls(urls):
    blocked = [
        "instagram.com",
        "facebook.com",
        "reddit.com",
        "youtube.com",
        "linkedin.com",
        "x.com",
        "twitter.com",
        "news.ycombinator.com",
    ]
    preferred = []
    for url in urls or []:
        if not any(b in url.lower() for b in blocked):
            preferred.append(url)
    return preferred[:5]


def _fill_event_blanks(event, ai_signals):
    """
    Fill-blanks-only merge of AI signals into a CyberEvent. Never overwrites
    non-blank fields. Respects data-integrity rules: activity events skip actor
    enrichment; victim required before any actor field is written.
    """
    if not ai_signals:
        return False

    changed = False
    is_activity = event.event_signal_type == "activity"

    if not is_activity and _is_blank(event.victim_org_name) and ai_signals.get("victim_org_name"):
        event.victim_org_name = ai_signals.get("victim_org_name")
        changed = True

    if _is_unknown_or_blank(event.industry):
        industry = _valid_value(ai_signals.get("industry"), ALLOWED_INDUSTRIES)
        if industry and industry != "Unknown":
            event.industry = industry
            changed = True

    if _is_unknown_or_blank(event.attack_type):
        attack_type = _valid_value(ai_signals.get("attack_type"), ALLOWED_ATTACK_TYPES)
        if attack_type and attack_type != "Unknown":
            event.attack_type = attack_type
            changed = True

    if _is_blank(event.country) and ai_signals.get("country"):
        event.country = ai_signals.get("country")
        changed = True

    # Derive region deterministically from country. Don't trust AI's region
    # value: it conflates US states with same-named countries (e.g. Georgia)
    # and produces inconsistent granularity. Country is the authoritative
    # geographic anchor; region is a one-to-one continent/subregion lookup.
    if event.country:
        derived_region = region_for_country(event.country)
        if derived_region and event.region != derived_region:
            event.region = derived_region
            changed = True
    elif _is_blank(event.region) and ai_signals.get("region"):
        # Fall through only if no country at all — accept AI region as a
        # last-resort hint, but it's still subject to validation downstream.
        event.region = ai_signals.get("region")
        changed = True

    if _is_blank(event.summary_short) and ai_signals.get("short_event_summary"):
        cleaned = _clean_model_text(ai_signals.get("short_event_summary"))
        if cleaned:
            event.summary_short = cleaned
            changed = True

    if not is_activity and event.victim_org_name:
        if _is_blank(event.actor_name) or _is_generic_actor_name(event.actor_name):
            actor_name = _clean_actor_name(ai_signals.get("actor_name"))
            if _is_valid_actor_name(actor_name):
                event.actor_name = actor_name
                changed = True

        if event.actor_name and _is_blank(event.actor_type):
            actor_type = _valid_value(ai_signals.get("actor_type"), ALLOWED_ACTOR_TYPES)
            if actor_type and actor_type != "unknown":
                event.actor_type = actor_type
                changed = True

        if event.actor_name and _is_blank(event.attribution_status):
            attribution_status = _valid_value(
                ai_signals.get("attribution_status"), ALLOWED_ATTRIBUTION_STATUS
            )
            if attribution_status and attribution_status != "unknown":
                event.attribution_status = attribution_status
                changed = True

    return changed


def _apply_data_integrity_rules(event):
    """
    Re-assert hard constraints after enrichment merge. Mirrors save_extraction's
    rules at the event level.
    """
    if event.event_signal_type == "activity":
        event.victim_org_name = None
        event.victim_org_normalized = None
        event.actor_name = None
        event.actor_type = None
        event.attribution_status = None
        return

    if _is_blank(event.victim_org_name):
        event.actor_name = None
        event.actor_type = None
        event.attribution_status = None
        return

    if _is_blank(event.actor_name):
        event.actor_type = None
        event.attribution_status = None


def _enrichment_still_incomplete(event):
    """
    True if the article-only call left blanks that web search could plausibly
    resolve. Mirrors the legacy _needs_web_enrichment thresholds.
    """
    if _is_unknown_or_blank(event.industry):
        return True
    if _is_unknown_or_blank(event.attack_type):
        return True
    if _missing_geography(event):
        return True

    if event.event_signal_type == "incident" and event.victim_org_name:
        if (
            _is_blank(event.actor_name)
            or _is_generic_actor_name(event.actor_name)
            or _is_blank(event.actor_type)
            or _is_blank(event.attribution_status)
        ):
            return True

    return False


def _accumulate_usage(totals, usage):
    if not usage:
        return
    for key in ("prompt_tokens", "completion_tokens", "total_tokens", "input_tokens", "output_tokens"):
        value = usage.get(key)
        if isinstance(value, (int, float)):
            totals[key] = totals.get(key, 0) + value


AUDITED_FIELDS = (
    "victim_org_name",
    "industry",
    "attack_type",
    "actor_name",
    "actor_type",
    "attribution_status",
    "country",
    "region",
    "summary_short",
)


def _audit_snapshot(event):
    return {field: getattr(event, field) for field in AUDITED_FIELDS}


def _diff_filled_fields(before, after):
    """
    Return the set of audited fields that went from blank/Unknown to a real
    value during enrichment. Mirrors the merge guard in _fill_event_blanks.
    """
    filled = []
    for field in AUDITED_FIELDS:
        prev = before.get(field)
        new = after.get(field)
        was_blank = prev is None or (isinstance(prev, str) and (not prev.strip() or prev.strip().lower() == "unknown"))
        has_now = new is not None and not (isinstance(new, str) and not new.strip())
        if was_blank and has_now and prev != new:
            filled.append(field)
    return filled


def _enrich_one_event(event_id):
    """
    Worker function. Loads event in this thread's session, performs enrichment,
    commits. Returns dict with stats for aggregation.
    """
    stats = {
        "event_id": event_id,
        "changed": False,
        "article_called": False,
        "web_called": False,
        "error": None,
        "usage": {},
    }

    event = CyberEvent.query.get(event_id)
    if not event:
        stats["error"] = "event_not_found"
        return stats

    audit_started_at = datetime.utcnow()
    started_perf = time.perf_counter()
    fields_before = _audit_snapshot(event)
    article_returned = None
    web_returned = None
    article_usage_captured = {}
    web_usage_captured = {}

    payload = _build_event_payload(event)
    error_message = None

    try:
        article_signals, article_usage = _call_xai_event_article_only(payload)
        stats["article_called"] = True
        article_returned = article_signals
        article_usage_captured = article_usage or {}
        _accumulate_usage(stats["usage"], article_usage)
        if _fill_event_blanks(event, article_signals):
            stats["changed"] = True
    except Exception as exc:
        error_message = f"article: {exc}"

    if _enrichment_still_incomplete(event):
        try:
            payload = _build_event_payload(event)
            web_signals, source_urls, web_usage = _call_xai_event_web_enrichment(payload)
            stats["web_called"] = True
            web_returned = web_signals
            web_usage_captured = web_usage or {}
            _accumulate_usage(stats["usage"], web_usage)
            if _fill_event_blanks(event, web_signals):
                stats["changed"] = True
            preferred = _filter_preferred_source_urls(source_urls)
            if preferred and not event.tags:
                event.tags = {"ai_event_sources": preferred}
            elif preferred and isinstance(event.tags, dict):
                event.tags = {**event.tags, "ai_event_sources": preferred}
        except Exception as exc:
            web_msg = f"web: {exc}"
            error_message = f"{error_message}; {web_msg}" if error_message else web_msg

    _apply_data_integrity_rules(event)

    event.last_enriched_at = datetime.utcnow()
    event.ai_event_error = error_message[:500] if error_message else None
    stats["error"] = error_message

    fields_after = _audit_snapshot(event)
    duration_ms = int((time.perf_counter() - started_perf) * 1000)

    audit = EnrichmentAuditLog(
        event_id=event_id,
        started_at=audit_started_at,
        duration_ms=duration_ms,
        article_called=stats["article_called"],
        web_called=stats["web_called"],
        fields_before=fields_before,
        fields_after=fields_after,
        article_returned=article_returned,
        web_returned=web_returned,
        fields_filled=_diff_filled_fields(fields_before, fields_after),
        article_usage=article_usage_captured or None,
        web_usage=web_usage_captured or None,
        error=(error_message[:500] if error_message else None),
    )
    db.session.add(audit)

    db.session.commit()
    return stats


def enrich_events(force=False, max_workers=5):
    """
    Public entry point. Enriches all events with fillable blanks using AI.
    Returns aggregated stats.
    """
    summary = {
        "events_considered": 0,
        "events_enriched": 0,
        "events_changed": 0,
        "article_calls": 0,
        "web_calls": 0,
        "failures": 0,
        "usage": {},
    }

    if not current_app.config.get("AI_ENRICHMENT_ENABLED"):
        return summary

    events = _events_needing_enrichment(force=force)
    summary["events_considered"] = len(events)
    if not events:
        return summary

    event_ids = [event.id for event in events]
    app = current_app._get_current_object()

    def _run(event_id):
        with app.app_context():
            try:
                return _enrich_one_event(event_id)
            except Exception as exc:
                db.session.rollback()
                return {"event_id": event_id, "error": str(exc), "usage": {}}

    workers = max(1, min(max_workers, len(event_ids)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_run, eid) for eid in event_ids]
        for future in as_completed(futures):
            stats = future.result()
            summary["events_enriched"] += 1
            if stats.get("changed"):
                summary["events_changed"] += 1
            if stats.get("article_called"):
                summary["article_calls"] += 1
            if stats.get("web_called"):
                summary["web_calls"] += 1
            if stats.get("error"):
                summary["failures"] += 1
            _accumulate_usage(summary["usage"], stats.get("usage") or {})

    return summary
