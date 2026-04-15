from datetime import datetime

from flask import Blueprint, jsonify, request

from app.models import EventSourceLink
from app.services.summary import get_filtered_events

events_bp = Blueprint("events", __name__, url_prefix="/api/events")


@events_bp.route("/", methods=["GET"])
def list_events():
    industry = request.args.get("industry")
    country = request.args.get("country")
    region = request.args.get("region")
    attack_type = request.args.get("attack_type")
    time_range = request.args.get("time_range")
    record_origin = request.args.get("record_origin")
    limit = request.args.get("limit", type=int)
    offset = request.args.get("offset", default=0, type=int)

    events = get_filtered_events(
        industry=industry,
        country=country,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
        record_origin=record_origin,
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
            "verification_level": event.verification_level,
            "record_origin": event.record_origin,
            "is_high_impact": event.is_high_impact,
            "victim_org_name": event.victim_org_name,
            "victim_org_normalized": event.victim_org_normalized,
            "victim_entity_type": event.victim_entity_type,
            "victim_display_label": event.victim_display_label,
            "industry": event.industry,
            "country": event.country,
            "region": event.region,
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
                event.event_occurred_at
                if event.record_origin == "historical_dataset" and event.event_occurred_at
                else event.last_seen_at or event.updated_at or event.created_at
            ),
            "summary_short": event.summary_short,
            "confidence_score": event.confidence_score,
            "confidence_level": event.confidence_level,
            "source_count": event.source_count,
            "primary_source_count": EventSourceLink.query.filter_by(
                cyber_event_id=event.id,
                is_primary_source=True,
            ).count(),
            "secondary_source_count": EventSourceLink.query.filter_by(
                cyber_event_id=event.id,
                is_primary_source=False,
            ).count(),
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