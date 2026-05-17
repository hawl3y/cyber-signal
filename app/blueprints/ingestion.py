from flask import Blueprint, jsonify, request

from app.extensions import db
from app.jobs.ingest_job import scheduled_ingest_job
from app.models import CyberEvent, EventSourceLink
from app.services.actor_recognition import attribute_events
from app.services.clustering import (
    create_event,
    find_best_match,
    find_candidate_events,
    get_extraction,
    attach_to_event,
    refresh_event,
)
from app.services.extraction import (
    mark_ready_for_clustering,
    run_rule_extraction,
    save_extraction,
)
from app.services.ingestion import (
    _ARTICLE_DOMAIN_TO_SOURCE,
    ingest_article_from_url,
)
from app.services.processing import (
    clean_article,
    mark_irrelevant,
    mark_ready_for_extraction,
    update_article,
)

ingestion_bp = Blueprint("ingestion", __name__, url_prefix="/api/ingest")


@ingestion_bp.route("/", methods=["POST"])
def trigger_ingestion():
    scheduled_ingest_job()
    return jsonify({"status": "ingestion started"})


def _run_pipeline_for_article(article):
    """
    Run process → extract → cluster → attribute on a single article.
    Returns a dict describing what happened.
    """
    cleaned = clean_article(article)
    update_article(article, cleaned)

    if not cleaned.get("is_relevant_incident"):
        mark_irrelevant(article)
        db.session.commit()
        return {"processing_status": "irrelevant"}

    mark_ready_for_extraction(article)

    signals = run_rule_extraction(article)
    save_extraction(article.id, signals)
    mark_ready_for_clustering(article)

    extraction = get_extraction(article)
    candidates = find_candidate_events(extraction)
    best_match = find_best_match(extraction, candidates)

    event_action = None
    event = None

    if best_match.score >= 0.8 and best_match.event_id is not None:
        event = CyberEvent.query.get(best_match.event_id)
        if event:
            attach_to_event(article, event)
            refresh_event(event.id)
            event_action = "merged"

    if event is None:
        event = create_event(article, extraction)
        refresh_event(event.id)
        event_action = "created"

    db.session.commit()

    attribute_events()

    event = CyberEvent.query.get(event.id)

    return {
        "processing_status": article.processing_status,
        "event_id": event.id,
        "event_action": event_action,
        "victim": event.victim_org_name,
        "attack_type": event.attack_type,
        "confidence_score": event.confidence_score,
        "source_count": event.source_count,
    }


@ingestion_bp.route("/url", methods=["POST"])
def ingest_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "url required"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "invalid url"}), 400

    article, status = ingest_article_from_url(url)

    if status == "already_exists":
        return jsonify({
            "status": "already_exists",
            "article_id": article.id,
            "title": article.title,
            "processing_status": article.processing_status,
        }), 200

    if status == "domain_not_allowed":
        return jsonify({
            "error": "domain_not_allowed",
            "allowed_domains": sorted(_ARTICLE_DOMAIN_TO_SOURCE.keys()),
        }), 400

    if status in ("fetch_failed", "insufficient_content"):
        return jsonify({"error": status}), 400

    result = _run_pipeline_for_article(article)

    return jsonify({
        "status": "ingested",
        "article_id": article.id,
        "title": article.title,
        "source": article.source_name,
        **result,
    }), 201
