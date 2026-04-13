from flask import Blueprint, jsonify, request

from app.services.summary import build_summary, build_map

summary_bp = Blueprint("summary", __name__, url_prefix="/api/summary")


@summary_bp.route("/", methods=["GET"])
def get_summary():
    industry = request.args.get("industry")
    country = request.args.get("country")
    region = request.args.get("region")
    city = request.args.get("city")
    attack_type = request.args.get("attack_type")
    event_status = request.args.get("event_status")

    return jsonify(
        build_summary(
            industry=industry,
            country=country,
            region=region,
            city=city,
            attack_type=attack_type,
            event_status=event_status,
        )
    )


@summary_bp.route("/map", methods=["GET"])
def get_map():
    industry = request.args.get("industry")
    country = request.args.get("country")
    region = request.args.get("region")
    city = request.args.get("city")
    attack_type = request.args.get("attack_type")
    event_status = request.args.get("event_status")

    return jsonify(
        build_map(
            industry=industry,
            country=country,
            region=region,
            city=city,
            attack_type=attack_type,
            event_status=event_status,
        )
    )