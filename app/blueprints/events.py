from flask import Blueprint, jsonify

from app.models import CyberEvent

events_bp = Blueprint("events", __name__, url_prefix="/api/events")


@events_bp.route("/", methods=["GET"])
def list_events():
    events = CyberEvent.query.all()

    results = [
        {
            "id": event.id,
            "canonical_title": event.canonical_title,
            "industry": event.industry,
            "country": event.country,
            "attack_type": event.attack_type,
            "confidence_level": event.confidence_level,
            "source_count": event.source_count,
        }
        for event in events
    ]

    return jsonify(results)