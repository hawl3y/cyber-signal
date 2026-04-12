from flask import Blueprint, jsonify

from app.jobs.cluster_events_job import cluster_events_job

clustering_bp = Blueprint("clustering", __name__, url_prefix="/api/cluster")


@clustering_bp.route("/", methods=["POST"])
def trigger_clustering():
    cluster_events_job()
    return jsonify({"status": "clustering complete"})