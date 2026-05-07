from datetime import datetime

from flask import Blueprint, jsonify, request

from app.models import EventSourceLink
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
    title = (event.canonical_title or "").lower()
    summary = (event.summary_short or "").lower()
    text = f"{title} {summary}"

    signal_rank = 0 if signal_type == "incident" else 1
    actor_rank = 0 if event.actor_name else 1
    status_rank = 0 if event.event_status == "confirmed" else 1

    high_impact_terms = [
        "mass-exploited",
        "mass exploited",
        "actively exploited",
        "widespread",
        "large-scale",
        "critical",
        "millions",
        "ransomware",
        "data breach",
        "wiper",
    ]

    high_impact_rank = 0 if any(term in text for term in high_impact_terms) else 1

    activity_context_rank = 0
    if signal_type == "activity":
        if not event.industry or event.industry == "Unknown":
            activity_context_rank = 1
        if not event.attack_type or event.attack_type == "Unknown":
            activity_context_rank = 1

    return (
        signal_rank,
        actor_rank,
        high_impact_rank,
        status_rank,
        activity_context_rank,
        -source_count,
        -timestamp,
    )


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
            "industry": event.industry,
            "country": event.country,
            "region": event.region,
            "attack_type": event.attack_type,
            "actor_name": event.actor_name,
            "actor_type": event.actor_type,
            "attribution_status": None if event.attribution_status == "unknown" else event.attribution_status,
            "event_signal_type": event.event_signal_type or "incident",
            "status": event.event_status,
            "confidence": event.confidence_level,
            "time": _format_event_time(event),
            "published_at": get_event_reference_time(event),
            "source_count": len({
                link.raw_article.source_name
                for link in event.event_sources
                if link.raw_article and link.raw_article.source_name
            }),
            "primary_source_count": EventSourceLink.query.filter_by(
                cyber_event_id=event.id,
                is_primary_source=True,
            ).count(),
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