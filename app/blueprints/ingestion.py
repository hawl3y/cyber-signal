from flask import Blueprint, jsonify

from app.jobs.ingest_job import scheduled_ingest_job

ingestion_bp = Blueprint("ingestion", __name__, url_prefix="/api/ingest")


@ingestion_bp.route("/", methods=["POST"])
def trigger_ingestion():
    scheduled_ingest_job()
    return jsonify({"status": "ingestion started"})