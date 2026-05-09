"""
Pipeline stage: scan recent articles for unrecognized threat-actor
candidates and persist them to actor_candidate_sightings.

Runs after attribute. The CLI (scripts/audit_unrecognized_actors.py)
reads from the persisted sightings to render a curator-facing report.
"""
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import ActorCandidateSighting, RawArticle
from app.services.actor_candidate_audit import (
    build_known_set,
    candidate_context,
    find_candidates_in_text,
    is_known,
    is_stop_word,
)


SCAN_WINDOW_DAYS = 14


def actor_candidate_audit_job():
    cutoff = datetime.utcnow() - timedelta(days=SCAN_WINDOW_DAYS)
    articles = RawArticle.query.filter(RawArticle.created_at >= cutoff).all()

    known = build_known_set()
    new_sightings = 0
    skipped = 0

    for article in articles:
        text = " ".join([
            article.title or "",
            article.summary or "",
            article.content or "",
        ])
        candidates = find_candidates_in_text(text)
        for candidate in candidates:
            if is_stop_word(candidate) or is_known(candidate, known):
                continue

            existing = ActorCandidateSighting.query.filter_by(
                candidate_name=candidate,
                raw_article_id=article.id,
            ).first()
            if existing:
                skipped += 1
                continue

            sighting = ActorCandidateSighting(
                candidate_name=candidate,
                raw_article_id=article.id,
                context_snippet=candidate_context(text, candidate),
            )
            db.session.add(sighting)
            try:
                db.session.flush()
                new_sightings += 1
            except IntegrityError:
                db.session.rollback()
                skipped += 1

    db.session.commit()
    return {
        "articles_scanned": len(articles),
        "new_sightings": new_sightings,
        "deduped": skipped,
    }
