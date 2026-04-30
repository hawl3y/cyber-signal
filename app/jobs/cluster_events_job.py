from app.extensions import db
from app.models import CyberEvent, EventSourceLink
from app.services.clustering import (
    get_ready_for_clustering,
    get_extraction,
    find_candidate_events,
    find_best_match,
    attach_to_event,
    create_event,
    refresh_event,
)


def _get_existing_event_for_article(article):
    """
    Return the currently linked event for this article, if one exists.

    Clustering should be additive and stable. We do not detach or delete
    existing event state during routine pipeline runs.
    """
    existing_link = EventSourceLink.query.filter_by(
        raw_article_id=article.id
    ).first()

    if not existing_link:
        return None

    return CyberEvent.query.get(existing_link.cyber_event_id)


def cluster_events_job():
    """
    Entry point for clustering stage.

    This stage is additive and idempotent:
    - keep existing article-event links stable
    - refresh existing events in place
    - only create a new event when no current link and no valid match exist
    """
    articles = get_ready_for_clustering()

    for article in articles:
        existing_event = _get_existing_event_for_article(article)
        if existing_event:
            article.processing_status = "clustered"
            db.session.flush()
            refresh_event(existing_event.id)
            continue

        extraction = get_extraction(article)

        candidates = find_candidate_events(extraction)
        best_match = find_best_match(extraction, candidates)

        if best_match.score >= 0.8 and best_match.event_id is not None:
            event = CyberEvent.query.get(best_match.event_id)
            if event:
                attach_to_event(article, event)
                refresh_event(event.id)
            else:
                new_event = create_event(article, extraction)
                refresh_event(new_event.id)
        else:
            new_event = create_event(article, extraction)
            refresh_event(new_event.id)

    db.session.commit()
    return True