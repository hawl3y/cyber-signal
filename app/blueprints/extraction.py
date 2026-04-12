from flask import Blueprint, jsonify

from app.jobs.extract_signals_job import extract_signals_job

extraction_bp = Blueprint("extraction", __name__, url_prefix="/api/extract")


@extraction_bp.route("/", methods=["POST"])
def trigger_extraction():
    extract_signals_job()
    return jsonify({"status": "extraction complete"})