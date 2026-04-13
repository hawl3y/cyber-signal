from flask import Blueprint, jsonify, request

from app.jobs.extract_signals_job import extract_signals_job
from app.models import ArticleExtraction

extraction_bp = Blueprint("extraction", __name__, url_prefix="/api/extract")


@extraction_bp.route("/", methods=["POST"])
def trigger_extraction():
    force = request.args.get("force", "false").lower() == "true"
    extract_signals_job(force=force)
    return jsonify({"status": "extraction complete", "force": force})


@extraction_bp.route("/debug", methods=["GET"])
def debug_extractions():
    """
    Debug endpoint to inspect extraction output.
    """
    limit = request.args.get("limit", default=10, type=int)

    rows = (
        ArticleExtraction.query
        .order_by(ArticleExtraction.created_at.desc())
        .limit(limit)
        .all()
    )

    return jsonify([
        {
            "id": r.id,
            "raw_article_id": r.raw_article_id,
            "victim_org_name": r.victim_org_name,
            "industry": r.industry,
            "attack_type": r.attack_type,
            "access_vector": r.access_vector,
            "impact_type": r.impact_type,
            "country": r.country,
            "region": r.region,
            "actor_name": r.actor_name,
            "attribution_status": r.attribution_status,
            "summary": r.short_event_summary,
        }
        for r in rows
    ])