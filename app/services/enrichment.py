from app.extensions import db
from app.models import CyberEvent, EventSourceLink, RawArticle, ArticleExtraction


def get_linked_articles(event_id):
    """
    Retrieve articles linked to an event.
    """
    links = EventSourceLink.query.filter_by(cyber_event_id=event_id).all()
    return [RawArticle.query.get(link.raw_article_id) for link in links]


def get_extractions(event_id):
    """
    Retrieve extractions for an event.
    """
    links = EventSourceLink.query.filter_by(cyber_event_id=event_id).all()
    article_ids = [link.raw_article_id for link in links]

    return ArticleExtraction.query.filter(
        ArticleExtraction.raw_article_id.in_(article_ids)
    ).all()


def aggregate_event_data(linked_articles, extractions):
    """
    Minimal aggregation logic.
    """
    if not linked_articles:
        return {}

    primary_article = linked_articles[0]

    return {
        "canonical_title": primary_article.title,
        "source_count": len(linked_articles),
    }


def update_event(event_id, event_data):
    """
    Update event record.
    """
    event = CyberEvent.query.get(event_id)

    if not event or not event_data:
        return event

    event.canonical_title = event_data.get("canonical_title", event.canonical_title)
    event.source_count = event_data.get("source_count", event.source_count)

    db.session.commit()
    return event