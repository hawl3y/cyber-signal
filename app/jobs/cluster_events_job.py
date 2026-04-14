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


def _detach_article_from_existing_event(article):
    """
    Remove any existing event link for this article so reclustering is clean.
    Delete orphaned events left behind by the detach.
    """
    existing_links = EventSourceLink.query.filter_by(
        raw_article_id=article.id
    ).all()

    for link in existing_links:
        old_event_id = link.cyber_event_id
        db.session.delete(link)
        db.session.flush()

        remaining_links = EventSourceLink.query.filter_by(
            cyber_event_id=old_event_id
        ).count()

        old_event = CyberEvent.query.get(old_event_id)
        if old_event:
            if remaining_links == 0:
                db.session.delete(old_event)
            else:
                old_event.source_count = remaining_links

        db.session.flush()


def cluster_events_job():
    """
    Entry point for clustering stage.

    This supports clean reclustering by removing any existing event links
    for an article before assigning it again.
    """
    articles = get_ready_for_clustering()

    for article in articles:
        _detach_article_from_existing_event(article)

        extraction = get_extraction(article)

        candidates = find_candidate_events(extraction)
        best_match = find_best_match(extraction, candidates)

        if best_match.score >= 0.8 and best_match.event_id is not None:
            event = CyberEvent.query.get(best_match.event_id)
            if event:
                attach_to_event(article, event)
                refresh_event(best_match.event_id)
            else:
                new_event = create_event(article, extraction)
                refresh_event(new_event.id)
        else:
            new_event = create_event(article, extraction)
            refresh_event(new_event.id)

    db.session.commit()
    return True