from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink
from app.services.processing import (
    clean_article,
    get_pending_articles,
    is_duplicate,
    mark_duplicate,
    mark_irrelevant,
    mark_ready_for_extraction,
    update_article,
)


def _remove_article_from_downstream(article):
    """
    Remove downstream extraction and clustering state for an article.

    This lets processing become authoritative again when an article is
    re-evaluated and found irrelevant.
    """
    # Delete extraction first
    extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()
    if extraction:
        db.session.delete(extraction)
        db.session.flush()

    # Remove any event links and clean up affected events
    links = EventSourceLink.query.filter_by(raw_article_id=article.id).all()

    for link in links:
        event_id = link.cyber_event_id
        db.session.delete(link)
        db.session.flush()

        remaining_links = EventSourceLink.query.filter_by(
            cyber_event_id=event_id
        ).count()

        event = CyberEvent.query.get(event_id)
        if not event:
            continue

        if remaining_links == 0:
            db.session.delete(event)
        else:
            event.source_count = remaining_links

        db.session.flush()


def process_articles_job(force=False):
    """
    Entry point for article processing.

    force=True re-runs relevance evaluation for non-duplicate articles already
    in the pipeline and removes downstream state for articles that are now
    considered irrelevant.
    """
    if force:
        articles = RawArticle.query.filter(
            RawArticle.is_duplicate.is_(False),
            RawArticle.processing_status.in_(
                ["pending", "irrelevant", "ready_for_extraction", "ready_for_clustering", "clustered"]
            ),
        ).all()
    else:
        articles = get_pending_articles()

    for article in articles:
        if is_duplicate(article):
            _remove_article_from_downstream(article)
            mark_duplicate(article)
            continue

        cleaned_data = clean_article(article)
        update_article(article, cleaned_data)

        if not cleaned_data.get("is_relevant_incident", False):
            _remove_article_from_downstream(article)
            mark_irrelevant(article)
            continue

        mark_ready_for_extraction(article)

    db.session.commit()
    return True