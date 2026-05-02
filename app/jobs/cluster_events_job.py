from app.extensions import db
from app.models import RawArticle, CyberEvent, EventSourceLink
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
    """
    existing_link = EventSourceLink.query.filter_by(
        raw_article_id=article.id
    ).first()

    if not existing_link:
        return None

    return CyberEvent.query.get(existing_link.cyber_event_id)


def _get_articles_for_clustering(force=False):
    if force:
        return RawArticle.query.filter(
            RawArticle.is_duplicate.is_(False),
            RawArticle.processing_status.in_(["ready_for_clustering", "clustered"]),
        ).all()

    return get_ready_for_clustering()


def _reassign_article_to_event(article, from_event, to_event):
    """
    Move an existing article-event link to a better matching event during an
    explicit forced reconciliation run.
    """
    link = EventSourceLink.query.filter_by(raw_article_id=article.id).first()
    if not link:
        return False

    if not to_event or link.cyber_event_id == to_event.id:
        return False

    old_event_id = link.cyber_event_id
    link.cyber_event_id = to_event.id
    article.processing_status = "clustered"
    db.session.flush()

    refresh_event(to_event.id)

    old_event = CyberEvent.query.get(old_event_id)
    if old_event:
        remaining_links = EventSourceLink.query.filter_by(
            cyber_event_id=old_event.id
        ).count()

        if remaining_links == 0:
            db.session.delete(old_event)
            db.session.flush()
        else:
            refresh_event(old_event.id)

    db.session.commit()
    return True


def cluster_events_job(force=False):
    """
    Entry point for clustering stage.

    Default mode is additive and stable.
    force=True enables explicit reconciliation of already-clustered articles
    against improved deterministic matching rules.
    """
    articles = _get_articles_for_clustering(force=force)

    for article in articles:
        existing_event = _get_existing_event_for_article(article)
        extraction = get_extraction(article)

        candidates = find_candidate_events(extraction)
        best_match = find_best_match(extraction, candidates)

        if existing_event:
            if (
                force
                and best_match.score >= 0.8
                and best_match.event_id is not None
                and best_match.event_id != existing_event.id
            ):
                better_event = CyberEvent.query.get(best_match.event_id)
                if better_event:
                    _reassign_article_to_event(article, existing_event, better_event)
                    continue

            article.processing_status = "clustered"
            db.session.flush()
            refresh_event(existing_event.id)
            continue

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