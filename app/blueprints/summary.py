from flask import Blueprint, jsonify

from app.services.summary import build_summary, build_map

summary_bp = Blueprint("summary", __name__, url_prefix="/api/summary")


@summary_bp.route("/", methods=["GET"])
def get_summary():
    return jsonify(build_summary())


@summary_bp.route("/map", methods=["GET"])
def get_map():
    return jsonify(build_map())