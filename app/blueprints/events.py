from datetime import datetime

from flask import Blueprint, jsonify, request

from app.services.summary import get_filtered_events, get_event_reference_time
from app.utils.sources import get_source_config

events_bp = Blueprint("events", __name__, url_prefix="/api/events")


def _format_event_time(event):
    ref = get_event_reference_time(event)
    if not ref:
        return None

    now = datetime.utcnow()
    delta = now - ref

    if delta.days == 0:
        hours = int(delta.total_seconds() // 3600)
        if hours <= 0:
            minutes = int(delta.total_seconds() // 60)
            return f"{max(minutes, 1)}m ago"
        return f"{hours}h ago"

    if delta.days < 7:
        return f"{delta.days}d ago"

    return ref.strftime("%Y-%m-%d")


def _event_priority(event):
    ref = get_event_reference_time(event)
    timestamp = ref.timestamp() if ref else 0
    source_count = event.source_count or 0
    signal_type = event.event_signal_type or "incident"
    score = event.confidence_score or 0

    signal_rank = 0 if signal_type == "incident" else 1
    impact_rank = 0 if event.is_high_impact else 1

    return (
        signal_rank,        # incidents before activity
        -score,             # higher trust score first
        impact_rank,        # high-impact first within trust band
        -source_count,      # more corroboration first
        -timestamp,         # most recent first
    )


_SOURCE_CLASS_FACTOR_LABELS = {
    "primary_disclosure": "primary-source disclosure",
    "official_alert": "official alert",
    "exploited_vulnerability": "known exploited vuln",
}


def _event_sources(event):
    """
    One entry per linked article, ordered by source weight desc then by
    publication recency desc — so the most authoritative outlet leads.
    """
    rows = []
    for link in event.event_sources:
        article = link.raw_article
        if not article:
            continue
        config = get_source_config(article.source_name) or {}
        display_label = (
            config.get("display_label")
            or article.publisher
            or article.source_name
        )
        rows.append({
            "source_name": article.source_name,
            "publisher": display_label,
            "title": article.title,
            "url": article.article_url,
            "published_at": article.published_at,
            "is_primary_source": bool(link.is_primary_source),
            "_weight": _source_weight_for_payload(article.source_name),
            "_ts": article.published_at.timestamp() if article.published_at else 0,
        })
    rows.sort(key=lambda r: (-r["_weight"], -r["_ts"]))
    for row in rows:
        row.pop("_weight", None)
        row.pop("_ts", None)
    return rows


def _source_weight_for_payload(source_name):
    """Mirror clustering._source_weight without importing the full module."""
    config = get_source_config(source_name) or {}
    source_class = config.get("source_class")
    if source_class == "primary_disclosure":
        return 100
    if source_class in {"official_alert", "exploited_vulnerability"}:
        return 80
    if config.get("tier_trusted_alone"):
        return 80
    if source_class == "incident_news":
        return 50
    return 30


def _score_factors(event):
    """
    Human-readable inputs that produced the event's confidence_score.
    Mirrors the deterministic logic in clustering._compute_confidence_score.
    """
    factors = []

    distinct_sources = len({
        link.raw_article.source_name
        for link in event.event_sources
        if link.raw_article and link.raw_article.source_name
    })
    if distinct_sources >= 2:
        factors.append(f"{distinct_sources} sources")
    elif distinct_sources == 1:
        factors.append("1 source")

    seen_class_labels = set()
    has_trusted_alone = False
    for link in event.event_sources:
        if not link.raw_article:
            continue
        config = get_source_config(link.raw_article.source_name) or {}
        klass = config.get("source_class")
        label = _SOURCE_CLASS_FACTOR_LABELS.get(klass)
        if label and label not in seen_class_labels:
            factors.append(label)
            seen_class_labels.add(label)
        if config.get("tier_trusted_alone"):
            has_trusted_alone = True

    if has_trusted_alone and not seen_class_labels:
        factors.append("tier-1 trusted source")

    if any(link.is_primary_source for link in event.event_sources):
        if "primary-source disclosure" not in seen_class_labels:
            factors.append("primary statement")

    if event.actor_name and event.event_signal_type == "incident":
        factors.append("attributed actor")

    return factors


def _display_context(event):
    """
    Pill rendered next to the victim/entity name on the card. Only emits a
    real industry — generic category labels ('Product / Platform',
    'Vulnerability', 'Security Activity') are taxonomic noise and the
    signal-type pill already conveys whether it's an incident or activity.
    """
    if event.industry and event.industry != "Unknown":
        return event.industry
    return None


@events_bp.route("/", methods=["GET"])
def list_events():
    industry = request.args.get("industry")
    region = request.args.get("region")
    attack_type = request.args.get("attack_type")
    time_range = request.args.get("time_range")
    limit = request.args.get("limit", type=int)
    offset = request.args.get("offset", default=0, type=int)

    events = get_filtered_events(
        industry=industry,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
    )

    if offset is None or offset < 0:
        offset = 0

    events = sorted(events, key=_event_priority)

    if offset:
        events = events[offset:]

    if limit is not None and limit >= 0:
        events = events[:limit]

    results = [
        {
            "id": event.id,
            "title": event.canonical_title,
            "summary": event.summary_short,
            "victim_name": event.victim_org_name,
            "display_entity": event.victim_display_label or event.victim_org_name,
            "entity_type": event.victim_entity_type or "unknown",
            "display_context": _display_context(event),
            "display_location": event.country or event.region,
            "display_attribution": event.actor_name,
            "industry": event.industry,
            "country": event.country,
            "region": event.region,
            "attack_type": event.attack_type,
            "actor_name": event.actor_name,
            "actor_type": event.actor_type,
            "attribution_status": None if event.attribution_status == "unknown" else event.attribution_status,
            "event_signal_type": event.event_signal_type or "incident",
            "status": event.event_status,
            "high_impact": event.is_high_impact,
            "confidence": event.confidence_level,
            "confidence_score": int(event.confidence_score) if event.confidence_score is not None else None,
            "score_factors": _score_factors(event),
            "time": _format_event_time(event),
            "published_at": get_event_reference_time(event),
            "source_count": len({
                link.raw_article.source_name
                for link in event.event_sources
                if link.raw_article and link.raw_article.source_name
            }),
            "primary_source_count": sum(
                1 for link in event.event_sources if link.is_primary_source
            ),
            "source_names": sorted({
                link.raw_article.source_name
                for link in event.event_sources
                if link.raw_article and link.raw_article.source_name
            }),
            "publishers": sorted({
                link.raw_article.publisher or link.raw_article.source_name
                for link in event.event_sources
                if link.raw_article and (link.raw_article.publisher or link.raw_article.source_name)
            }),
            "sources": _event_sources(event),
            "primary_cve_id": event.primary_cve_id,
        }
        for event in events
    ]

    return jsonify(results)