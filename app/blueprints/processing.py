from flask import Blueprint, jsonify, request

from app.jobs.process_articles_job import process_articles_job

processing_bp = Blueprint("processing", __name__, url_prefix="/api/process")


@processing_bp.route("/", methods=["POST"])
def trigger_processing():
    force = request.args.get("force", "false").lower() == "true"
    process_articles_job(force=force)
    return jsonify({
        "status": "processing complete",
        "force": force,
    })