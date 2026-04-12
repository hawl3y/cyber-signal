from flask import Blueprint, jsonify

from app.models import CyberEvent

filters_bp = Blueprint("filters", __name__, url_prefix="/api/filters")


@filters_bp.route("/", methods=["GET"])
def get_filters():
    events = CyberEvent.query.all()

    industries = sorted({e.industry for e in events if e.industry})
    countries = sorted({e.country for e in events if e.country})
    attack_types = sorted({e.attack_type for e in events if e.attack_type})

    return jsonify({
        "industries": industries,
        "countries": countries,
        "attack_types": attack_types,
    })