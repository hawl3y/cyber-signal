from flask import Blueprint, jsonify

from app.jobs.process_articles_job import process_articles_job

processing_bp = Blueprint("processing", __name__, url_prefix="/api/process")


@processing_bp.route("/", methods=["POST"])
def trigger_processing():
    process_articles_job()
    return jsonify({"status": "processing complete"})