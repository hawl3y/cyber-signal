from flask import Blueprint, jsonify

from app.jobs.enrich_events_job import enrich_events_job

enrichment_bp = Blueprint("enrichment", __name__, url_prefix="/api/enrich")


@enrichment_bp.route("/", methods=["POST"])
def trigger_enrichment():
    enrich_events_job()
    return jsonify({"status": "enrichment complete"})