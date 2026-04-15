from flask import Blueprint, jsonify, request

from app.services.summary import build_summary, build_map

summary_bp = Blueprint("summary", __name__, url_prefix="/api/summary")


@summary_bp.route("/", methods=["GET"])
def get_summary():
    industry = request.args.get("industry")
    country = request.args.get("country")
    region = request.args.get("region")
    attack_type = request.args.get("attack_type")
    time_range = request.args.get("time_range")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    return jsonify(
        build_summary(
            industry=industry,
            country=country,
            region=region,
            attack_type=attack_type,
            time_range=time_range,
            start_date=start_date,
            end_date=end_date,
        )
    )


@summary_bp.route("/map", methods=["GET"])
def get_map():
    industry = request.args.get("industry")
    country = request.args.get("country")
    region = request.args.get("region")
    attack_type = request.args.get("attack_type")
    time_range = request.args.get("time_range")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    return jsonify(
        build_map(
            industry=industry,
            country=country,
            region=region,
            attack_type=attack_type,
            time_range=time_range,
            start_date=start_date,
            end_date=end_date,
        )
    )