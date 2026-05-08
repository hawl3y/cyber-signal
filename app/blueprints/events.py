from datetime import datetime

from flask import Blueprint, jsonify, request

from app.services.summary import get_filtered_events, get_event_reference_time

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

    signal_rank = 0 if signal_type == "incident" else 1
    actor_rank = 0 if event.actor_name else 1
    impact_rank = 0 if event.is_high_impact else 1
    status_rank = 0 if event.event_status == "confirmed" else 1

    return (
        signal_rank,
        actor_rank,
        impact_rank,
        status_rank,
        -source_count,
        -timestamp,
    )


def _display_context(event):
    if event.victim_entity_type == "vulnerability":
        return "Vulnerability"

    if event.victim_entity_type == "product_or_platform":
        return "Product / Platform"

    if event.event_signal_type == "activity":
        return "Security Activity"

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
        }
        for event in events
    ]

    return jsonify(results)