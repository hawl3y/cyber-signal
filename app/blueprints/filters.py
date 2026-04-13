from flask import Blueprint, jsonify, request

from app.services.summary import get_filtered_events


def _clean_filter_values(values):
    cleaned = {}
    for value in values:
        if not value:
            continue

        normalized = value.strip()
        if not normalized:
            continue

        key = normalized.lower()
        if key not in cleaned:
            cleaned[key] = normalized

    return sorted(cleaned.values(), key=lambda v: v.lower())

filters_bp = Blueprint("filters", __name__, url_prefix="/api/filters")


@filters_bp.route("/", methods=["GET"])
def get_filters():
    industry = request.args.get("industry")
    country = request.args.get("country")
    region = request.args.get("region")
    city = request.args.get("city")
    attack_type = request.args.get("attack_type")
    event_status = request.args.get("event_status")

    events = get_filtered_events(
        industry=industry,
        country=country,
        region=region,
        city=city,
        attack_type=attack_type,
        event_status=event_status,
    )

    industries = _clean_filter_values(e.industry for e in events)
    regions = _clean_filter_values(e.region for e in events)
    countries = _clean_filter_values(e.country for e in events)
    cities = _clean_filter_values(e.city for e in events)
    attack_types = _clean_filter_values(e.attack_type for e in events)
    event_statuses = _clean_filter_values(e.event_status for e in events)

    return jsonify({
        "industries": industries,
        "regions": regions,
        "countries": countries,
        "cities": cities,
        "attack_types": attack_types,
        "event_statuses": event_statuses,
    })