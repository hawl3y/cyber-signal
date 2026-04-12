from flask import Blueprint, jsonify

from app.jobs.score_events_job import score_events_job

scoring_bp = Blueprint("scoring", __name__, url_prefix="/api/score")


@scoring_bp.route("/", methods=["POST"])
def trigger_scoring():
    score_events_job()
    return jsonify({"status": "scoring complete"})