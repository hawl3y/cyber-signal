from flask import Blueprint, jsonify, request
from datetime import datetime
from app.services.summary import get_filtered_events

events_bp = Blueprint("events", __name__, url_prefix="/api/events")


@events_bp.route("/", methods=["GET"])
def list_events():
    industry = request.args.get("industry")
    country = request.args.get("country")
    region = request.args.get("region")
    city = request.args.get("city")
    attack_type = request.args.get("attack_type")
    event_status = request.args.get("event_status")
    limit = request.args.get("limit", type=int)
    offset = request.args.get("offset", default=0, type=int)

    events = get_filtered_events(
        industry=industry,
        country=country,
        region=region,
        city=city,
        attack_type=attack_type,
        event_status=event_status,
    )

    if offset is None or offset < 0:
        offset = 0

    events = sorted(
        events,
        key=lambda e: e.last_seen_at or e.created_at,
        reverse=True,
    )

    if offset:
        events = events[offset:]

    if limit is not None and limit >= 0:
        events = events[:limit]

    results = [
        {
            "id": event.id,
            "canonical_title": event.canonical_title,
            "event_status": event.event_status,
            "victim_org_name": event.victim_org_name,
            "industry": event.industry,
            "country": event.country,
            "region": event.region,
            "city": event.city,
            "geography_type": event.geography_type,
            "attack_type": event.attack_type,
            "access_vector": event.access_vector,
            "impact_type": event.impact_type,
            "actor_name": event.actor_name,
            "actor_type": event.actor_type,
            "attribution_status": event.attribution_status,
            "vuln_status": event.vuln_status,
            "zero_day_flag": event.zero_day_flag,
            "recency_bucket": (
                lambda ref: (
                    "today"
                    if ref and (datetime.utcnow() - ref).days == 0
                    else "recent"
                    if ref and (datetime.utcnow() - ref).days <= 7
                    else "older"
                )
            )(
                event.last_seen_at
                or event.updated_at
                or event.created_at
            ),
            "summary_short": event.summary_short,
            "confidence_score": event.confidence_score,
            "confidence_level": event.confidence_level,
            "source_count": event.source_count,
            "first_seen_at": event.first_seen_at,
            "last_seen_at": event.last_seen_at,
            "event_occurred_at": event.event_occurred_at,
            "created_at": event.created_at,
            "updated_at": event.updated_at,
            "last_enriched_at": event.last_enriched_at,
            "last_confidence_scored_at": event.last_confidence_scored_at,
        }
        for event in events
    ]

    return jsonify(results)