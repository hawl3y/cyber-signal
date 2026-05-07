from datetime import datetime
import json
import re

import requests
from flask import current_app

from app.models import ArticleExtraction
from app.utils.sources import get_source_config


ALLOWED_INDUSTRIES = {
    "Technology",
    "Healthcare",
    "Financial Services",
    "Education",
    "Government",
    "Energy",
    "Transportation",
    "Media",
    "Unknown",
}

ALLOWED_ATTACK_TYPES = {
    "Ransomware",
    "Phishing",
    "DDoS",
    "Data Breach",
    "Malware",
    "Exploitation",
    "Account Compromise",
    "Unknown",
}

ALLOWED_ACTOR_TYPES = {
    "nation_state",
    "cybercriminal",
    "hacktivist",
    "insider",
    "unknown",
}

ALLOWED_ATTRIBUTION_STATUS = {
    "claimed",
    "suspected",
    "confirmed",
    "unknown",
}


GENERIC_ACTOR_NAMES = {
    "hackers",
    "threat actors",
    "attackers",
    "cybercriminals",
    "ransomware group",
    "ransomware gang",
    "hacktivist group",
    "iran-backed hackers",
    "state-backed hackers",
}


def _truncate_text(value, limit=1500):
    if not value:
        return None

    value = str(value).strip()
    if len(value) <= limit:
        return value

    return value[:limit].rsplit(" ", 1)[0]


def _article_payload(article):
    return {
        "title": _truncate_text(article.title, 500),
        "summary": _truncate_text(article.summary, 1500),
        "content_excerpt": _truncate_text(article.content, 2500),
        "source_name": article.source_name,
        "publisher": article.publisher,
    }


def _needs_article_ai_enrichment(signals):
    return (
        not signals.get("victim_org_name")
        or signals.get("industry") in {None, "Unknown"}
        or signals.get("attack_type") in {None, "Unknown"}
        or (
            not signals.get("actor_name")
            and signals.get("attack_type") not in {None, "Unknown"}
        )
    )


def _is_generic_actor_name(value):
    if not value:
        return True

    cleaned = str(value).strip().lower()
    cleaned = re.sub(r"\s+", " ", cleaned)

    if cleaned in GENERIC_ACTOR_NAMES:
        return True

    generic_fragments = [
        "unknown",
        "unnamed",
        "hackers",
        "threat actors",
        "attackers",
        "ransomware group",
        "ransomware gang",
        "hacktivist group",
    ]

    return any(fragment == cleaned for fragment in generic_fragments)


def _is_valid_actor_name(value):
    if not value:
        return False

    cleaned = re.sub(r"\s+", " ", str(value).strip())
    if not cleaned:
        return False

    lowered = cleaned.lower()

    if lowered.startswith(("a ", "an ", "the ")):
        return False

    if len(cleaned.split()) > 5:
        return False

    has_proper_case = bool(re.search(r"\b[A-Z][A-Za-z0-9._-]{2,}\b", cleaned))
    has_acronym = bool(re.search(r"\b[A-Z0-9]{3,}\b", cleaned))
    has_handle_style = bool(
        re.search(
            r"\b[A-Za-z0-9._-]*(?:team|group|crew|unit|spider|bear|kitten|panda|hunters|lock|crypt|cartel|cl0p|black|dark|storm|sandworm)[A-Za-z0-9._-]*\b",
            cleaned,
            flags=re.IGNORECASE,
        )
    )

    return has_proper_case or has_acronym or has_handle_style


def _is_enrichment_complete(signals):
    return (
        signals.get("victim_org_name")
        and signals.get("industry") not in {None, "Unknown"}
        and signals.get("attack_type") not in {None, "Unknown"}
        and _is_valid_actor_name(signals.get("actor_name"))
        and not _is_generic_actor_name(signals.get("actor_name"))
        and signals.get("actor_type")
        and signals.get("attribution_status")
    )


def _needs_actor_upgrade(actor_name):
    if not actor_name:
        return True

    if _is_generic_actor_name(actor_name):
        return True

    cleaned = re.sub(r"\s+", " ", str(actor_name).strip())

    if len(cleaned.split()) >= 3:
        return True

    if not re.search(r"[A-Z]", cleaned):
        return True

    return False


def _needs_web_enrichment(article, signals):
    source_config = get_source_config(article.source_name)
    signal_kind = source_config.get("signal_kind") if source_config else None

    if signals.get("ai_web_enriched"):
        return False

    victim = signals.get("victim_org_name")
    attack_type = signals.get("attack_type")
    industry = signals.get("industry")
    actor_name = signals.get("actor_name")

    if signal_kind == "incident":
        if not victim:
            return False

        if industry in {None, "Unknown"} or attack_type in {None, "Unknown"}:
            return True

        if _needs_actor_upgrade(actor_name):
            return True

        if not signals.get("actor_type") or not signals.get("attribution_status"):
            return True

        return False

    if signal_kind == "activity":
        if industry in {None, "Unknown"} or attack_type in {None, "Unknown"}:
            return True

        if not signals.get("country") and not signals.get("region"):
            return True

        return False

    return False


def _extract_json_object(value):
    if not value:
        return None

    value = value.strip()

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", value, flags=re.DOTALL)
    if not match:
        return None

    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

def _clean_model_text(value):
    if not value:
        return None

    cleaned = re.sub(
        r"<grok:render.*?</grok:render>",
        "",
        str(value),
        flags=re.DOTALL,
    )
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned or None


def _extract_output_text_from_responses_api(data):
    output_texts = []

    for item in data.get("output", []):
        if item.get("type") != "message":
            continue

        for content in item.get("content", []):
            if content.get("type") == "output_text":
                output_texts.append(content.get("text", ""))

    return "\n".join(output_texts).strip()


def _extract_source_urls_from_responses_api(data):
    urls = []

    for item in data.get("output", []):
        if item.get("type") != "message":
            continue

        for content in item.get("content", []):
            for annotation in content.get("annotations", []) or []:
                url = annotation.get("url")
                if url and url not in urls:
                    urls.append(url)

    return urls


def _valid_value(value, allowed):
    if value in allowed:
        return value
    return None


def _base_xai_config():
    api_key = current_app.config.get("XAI_API_KEY")
    base_url = current_app.config.get("XAI_BASE_URL", "https://api.x.ai/v1")
    model = current_app.config.get("XAI_MODEL", "grok-4-1-fast-non-reasoning")

    return api_key, base_url.rstrip("/"), model


def _call_xai_article_only(article, current_signals):
    api_key, base_url, model = _base_xai_config()

    if not api_key:
        return None

    prompt = {
        "task": "Extract cyber incident fields from the supplied article fields.",
        "rules": [
            "Use only the provided title, summary, and content_excerpt.",
            "Do not use outside knowledge.",
            "Do not infer facts that are not supported by the supplied article fields.",
            "Return null when a field is not supported.",
            "Return JSON only.",
            "Do not include markdown.",
            "Do not invent victim names, industries, countries, threat actors, or attack types.",
        ],
        "actor_extraction_rules": [
            "Extract actor_name when the supplied article fields explicitly name or describe the claimed, suspected, or confirmed actor.",
            "Actor names may be proper group names or explicit descriptive phrases.",
            "Prefer proper group names over generic phrases only when the proper group name appears in the supplied article fields.",
            "If the article says a group claimed responsibility, set attribution_status to 'claimed'.",
            "If the article says an actor is linked to, suspected, believed, or attributed by researchers, set attribution_status to 'suspected'.",
            "If the article says officials, the victim, or researchers confirmed attribution, set attribution_status to 'confirmed'.",
            "If the actor is described as hacktivist, actor_type should be 'hacktivist'.",
            "If both hacktivist and state-backed/government-backed language appear, actor_type should be 'hacktivist' unless the article explicitly calls the actor a nation-state group.",
            "If the actor is described only as state-backed, state-sponsored, nation-state, or backed by a government, actor_type should be 'nation_state'.",
            "If the actor is described as ransomware, extortion, financially motivated, or criminal, actor_type should be 'cybercriminal'.",
        ],
        "allowed_values": {
            "industry": sorted(ALLOWED_INDUSTRIES),
            "attack_type": sorted(ALLOWED_ATTACK_TYPES),
            "actor_type": sorted(ALLOWED_ACTOR_TYPES),
            "attribution_status": sorted(ALLOWED_ATTRIBUTION_STATUS),
        },
        "current_signals": current_signals,
        "article": _article_payload(article),
        "return_schema": {
            "victim_org_name": "string or null",
            "industry": "one allowed industry value or null",
            "attack_type": "one allowed attack type value or null",
            "actor_name": "string or null",
            "actor_type": "one allowed actor_type value or null",
            "attribution_status": "one allowed attribution_status value or null",
            "country": "string or null",
            "region": "string or null",
            "short_event_summary": "one sentence or null",
        },
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
                    "content": "You extract structured cyber incident fields. Return JSON only. No markdown.",
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt),
                },
            ],
            "temperature": 0,
            "max_tokens": 500,
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

    return _extract_json_object(output_text)


def _call_xai_web_enrichment(article, current_signals):
    api_key, base_url, model = _base_xai_config()

    if not api_key:
        return None, []

    prompt = {
        "task": "Enrich a cyber incident record using web search and return structured JSON.",
        "rules": [
            "Use the supplied article fields and current_signals as the starting point.",
            "Use web search to corroborate missing or weak fields.",
            "Prefer authoritative reporting, official disclosures, victim statements, government advisories, or reputable cyber news sources.",
            "Do not guess.",
            "Return null for fields that cannot be corroborated.",
            "Return JSON only.",
            "Do not include markdown.",
            "Do not include citations or citation markup inside field values.",
            "Return no more than five source URLs if sources are included.",
            "Preserve existing current_signals unless web search clearly supports a better value.",
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
            "For actor_name, prefer the most specific named threat actor or group.",
            "Do not return generic actor names such as hackers, attackers, threat actors, Iran-backed hackers, or ransomware group when a specific group name is available.",
            "If the responsible group claimed responsibility, attribution_status should be 'claimed'.",
            "If reporting says the actor is suspected, linked, believed, or attributed, attribution_status should be 'suspected'.",
            "If reporting says attribution is confirmed by officials, the victim, or credible researchers, attribution_status should be 'confirmed'.",
            "Classify hacktivist groups as actor_type 'hacktivist'.",
            "Classify financially motivated ransomware/extortion groups as actor_type 'cybercriminal'.",
            "Classify state-sponsored or nation-state operators as actor_type 'nation_state'.",
        ],
        "allowed_values": {
            "industry": sorted(ALLOWED_INDUSTRIES),
            "attack_type": sorted(ALLOWED_ATTACK_TYPES),
            "actor_type": sorted(ALLOWED_ACTOR_TYPES),
            "attribution_status": sorted(ALLOWED_ATTRIBUTION_STATUS),
        },
        "current_signals": current_signals,
        "article": _article_payload(article),
        "search_query_hint": "cyberattack victim threat actor claimed responsibility industry attack type",
        "return_schema": {
            "victim_org_name": "string or null",
            "industry": "one allowed industry value or null",
            "attack_type": "one allowed attack type value or null",
            "actor_name": "string or null",
            "actor_type": "one allowed actor_type value or null",
            "attribution_status": "one allowed attribution_status value or null",
            "country": "string or null",
            "region": "string or null",
            "short_event_summary": "one sentence or null",
        },
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
            "tools": [
                {
                    "type": "web_search",
                }
            ],
            "temperature": 0,
            "max_output_tokens": 500,
        },
        timeout=60,
    )

    response.raise_for_status()
    data = response.json()

    output_text = _extract_output_text_from_responses_api(data)
    source_urls = _extract_source_urls_from_responses_api(data)

    return _extract_json_object(output_text), source_urls


def _merge_article_ai_signals(rule_signals, ai_signals):
    if not ai_signals:
        return rule_signals

    merged = dict(rule_signals)

    if not merged.get("victim_org_name") and ai_signals.get("victim_org_name"):
        merged["victim_org_name"] = ai_signals.get("victim_org_name")

    if merged.get("industry") in {None, "Unknown"}:
        industry = _valid_value(ai_signals.get("industry"), ALLOWED_INDUSTRIES)
        if industry:
            merged["industry"] = industry

    if merged.get("attack_type") in {None, "Unknown"}:
        attack_type = _valid_value(ai_signals.get("attack_type"), ALLOWED_ATTACK_TYPES)
        if attack_type:
            merged["attack_type"] = attack_type

    if not merged.get("country") and ai_signals.get("country"):
        merged["country"] = ai_signals.get("country")

    if not merged.get("region") and ai_signals.get("region"):
        merged["region"] = ai_signals.get("region")

    if not merged.get("short_event_summary") and ai_signals.get("short_event_summary"):
        merged["short_event_summary"] = ai_signals.get("short_event_summary")

    actor_name = ai_signals.get("actor_name")
    if _is_valid_actor_name(actor_name) and not merged.get("actor_name"):
        merged["actor_name"] = actor_name

    actor_type = _valid_value(ai_signals.get("actor_type"), ALLOWED_ACTOR_TYPES)
    if actor_type and not merged.get("actor_type"):
        merged["actor_type"] = actor_type

    attribution_status = _valid_value(
        ai_signals.get("attribution_status"),
        ALLOWED_ATTRIBUTION_STATUS,
    )
    if attribution_status and not merged.get("attribution_status"):
        merged["attribution_status"] = attribution_status

    merged["ai_article_enriched"] = True
    merged["ai_article_raw"] = ai_signals

    return merged


def _merge_web_enrichment_signals(current_signals, web_signals, source_urls):
    if not web_signals:
        return current_signals

    merged = dict(current_signals)

    if not merged.get("victim_org_name") and web_signals.get("victim_org_name"):
        merged["victim_org_name"] = web_signals.get("victim_org_name")

    if merged.get("industry") in {None, "Unknown"}:
        industry = _valid_value(web_signals.get("industry"), ALLOWED_INDUSTRIES)
        if industry:
            merged["industry"] = industry

    if merged.get("attack_type") in {None, "Unknown"}:
        attack_type = _valid_value(web_signals.get("attack_type"), ALLOWED_ATTACK_TYPES)
        if attack_type:
            merged["attack_type"] = attack_type

    if not merged.get("country") and web_signals.get("country"):
        merged["country"] = web_signals.get("country")

    if not merged.get("region") and web_signals.get("region"):
        merged["region"] = web_signals.get("region")

    if not merged.get("short_event_summary") and web_signals.get("short_event_summary"):
        merged["short_event_summary"] = _clean_model_text(
            web_signals.get("short_event_summary")
        )

    web_actor_name = web_signals.get("actor_name")
    if _is_valid_actor_name(web_actor_name) and (
        not merged.get("actor_name") or _is_generic_actor_name(merged.get("actor_name"))
    ):
        merged["actor_name"] = web_actor_name

    actor_type = _valid_value(web_signals.get("actor_type"), ALLOWED_ACTOR_TYPES)
    if actor_type:
        merged["actor_type"] = actor_type

    attribution_status = _valid_value(
        web_signals.get("attribution_status"),
        ALLOWED_ATTRIBUTION_STATUS,
    )
    if attribution_status:
        merged["attribution_status"] = attribution_status

    merged["ai_web_enriched"] = True
    merged["ai_web_enriched_at"] = datetime.utcnow().isoformat()
    merged["ai_web_raw"] = web_signals

    preferred_sources = [
        url for url in source_urls
        if not any(
            blocked in url.lower()
            for blocked in [
                "instagram.com",
                "facebook.com",
                "reddit.com",
                "youtube.com",
                "linkedin.com",
                "x.com",
                "twitter.com",
                "news.ycombinator.com",
            ]
        )
    ]

    merged["ai_web_sources"] = preferred_sources[:5]

    return merged


def _merge_existing_web_enrichment(article, signals):
    extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()

    if not extraction or not extraction.extracted_signals:
        return signals

    previous = extraction.extracted_signals

    if not previous.get("ai_web_enriched"):
        return signals

    merged = dict(signals)

    for field in [
        "victim_org_name",
        "industry",
        "attack_type",
        "actor_name",
        "actor_type",
        "attribution_status",
        "country",
        "region",
        "short_event_summary",
    ]:
        if previous.get(field) and (
            not merged.get(field) or merged.get(field) == "Unknown"
        ):
            merged[field] = previous.get(field)

    if previous.get("actor_name") and _is_valid_actor_name(previous.get("actor_name")):
        merged["actor_name"] = previous.get("actor_name")

    if previous.get("actor_type"):
        merged["actor_type"] = previous.get("actor_type")

    if previous.get("attribution_status"):
        merged["attribution_status"] = previous.get("attribution_status")

    merged["ai_web_enriched"] = True
    merged["ai_web_enriched_at"] = previous.get("ai_web_enriched_at")
    merged["ai_web_raw"] = previous.get("ai_web_raw")
    merged["ai_web_sources"] = previous.get("ai_web_sources")

    return merged


def enrich_with_ai_if_needed(article, rule_signals):
    merged = _merge_existing_web_enrichment(article, dict(rule_signals))

    if not current_app.config.get("AI_ENRICHMENT_ENABLED"):
        return merged

    if _needs_article_ai_enrichment(merged):
        try:
            article_ai_signals = _call_xai_article_only(article, merged)
            merged = _merge_article_ai_signals(merged, article_ai_signals)
        except Exception as exc:
            merged["ai_article_enriched"] = False
            merged["ai_article_error"] = str(exc)

    merged = _merge_existing_web_enrichment(article, merged)

    if _is_enrichment_complete(merged):
        merged["ai_enriched"] = True
        return merged

    if _needs_web_enrichment(article, merged):
        try:
            web_signals, source_urls = _call_xai_web_enrichment(article, merged)
            merged = _merge_web_enrichment_signals(merged, web_signals, source_urls)
        except Exception as exc:
            merged["ai_web_enriched"] = False
            merged["ai_web_error"] = str(exc)

    merged["ai_enriched"] = bool(
        merged.get("ai_article_enriched") or merged.get("ai_web_enriched")
    )

    return merged