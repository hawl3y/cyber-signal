from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink


def get_ready_for_clustering():
    """
    Fetch articles ready for clustering.
    """
    return RawArticle.query.filter_by(processing_status="ready_for_clustering").all()


def get_extraction(article):
    """
    Retrieve extraction data for an article.
    """
    return ArticleExtraction.query.filter_by(raw_article_id=article.id).first()


def find_candidate_events(extraction):
    """
    Minimal placeholder: no candidate matching yet.
    """
    return []


def find_best_match(extraction, candidates):
    """
    Minimal placeholder match result.
    """
    class Result:
        score = 0
        event_id = None

    return Result()


def attach_to_event(article, event):
    """
    Link article to event.
    """
    link = EventSourceLink(
        cyber_event_id=event.id,
        raw_article_id=article.id,
        match_score=1.0,
        is_primary_source=False,
    )

    db.session.add(link)
    db.session.commit()
    return link


def create_event(article, extraction):
    """
    Create a new cyber event from article + extraction.
    """
    event = CyberEvent(
        canonical_title=article.title or "Untitled Event",
        slug=f"event-{article.id}",
        event_status="open",
        victim_org_name=extraction.victim_org_name if extraction else None,
        industry=extraction.industry if extraction else None,
        attack_type=extraction.attack_type if extraction else None,
        source_count=1,
    )

    db.session.add(event)
    db.session.commit()
    return event


def refresh_event(event_id):
    """
    Minimal placeholder for event refresh.
    """
    return True