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
    Find candidate events using victim organization as the primary key,
    with a narrow actor-based fallback only when victim extraction is missing.
    """
    if not extraction:
        return []

    if extraction.victim_org_normalized:
        return CyberEvent.query.filter_by(
            victim_org_normalized=extraction.victim_org_normalized
        ).all()

    if extraction.victim_org_name:
        return CyberEvent.query.filter_by(
            victim_org_name=extraction.victim_org_name
        ).all()

    if extraction.actor_name:
        actor_candidates = CyberEvent.query.filter_by(
            actor_name=extraction.actor_name
        ).all()
        if actor_candidates:
            return actor_candidates

    return []


def find_best_match(extraction, candidates):
    """
    Return a simple deterministic match result.
    """
    class Result:
        def __init__(self, score=0, event_id=None):
            self.score = score
            self.event_id = event_id

    if not extraction or not candidates:
        return Result()

    candidate = candidates[0]
    return Result(score=1.0, event_id=candidate.id)


def attach_to_event(article, event):
    """
    Link article to event if not already linked, mark article as clustered,
    and keep source_count aligned with actual links.
    """
    existing_link = EventSourceLink.query.filter_by(
        cyber_event_id=event.id,
        raw_article_id=article.id,
    ).first()

    if not existing_link:
        link = EventSourceLink(
            cyber_event_id=event.id,
            raw_article_id=article.id,
            match_score=1.0,
            is_primary_source=False,
        )
        db.session.add(link)

    article.processing_status = "clustered"
    db.session.flush()

    event.source_count = EventSourceLink.query.filter_by(
        cyber_event_id=event.id
    ).count()

    db.session.commit()
    return existing_link if existing_link else link


def create_event(article, extraction):
    """
    Create a new cyber event from article + extraction, or return the
    existing event for this article slug if it already exists.
    """
    slug = f"event-{article.id}"

    existing_event = CyberEvent.query.filter_by(slug=slug).first()
    if existing_event:
        return existing_event

    event = CyberEvent(
        canonical_title=article.title or "Untitled Event",
        slug=slug,
        event_status="open",
        victim_org_name=extraction.victim_org_name if extraction else None,
        victim_org_normalized=(
            extraction.victim_org_normalized if extraction else None
        ),
        industry=extraction.industry if extraction else None,
        attack_type=extraction.attack_type if extraction else None,
        access_vector=extraction.access_vector if extraction else None,
        impact_type=extraction.impact_type if extraction else None,
        attribution_status=(
            extraction.attribution_status if extraction else "unattributed"
        ),
        vuln_status=extraction.vuln_status if extraction else None,
        zero_day_flag=extraction.zero_day_flag if extraction else False,
        region=extraction.region if extraction else None,
        country=extraction.country if extraction else None,
        city=extraction.city if extraction else None,
        summary_short=extraction.short_event_summary if extraction else None,
        source_count=0,  # important: start at 0, not 1
    )

    db.session.add(event)
    db.session.flush()

    link = EventSourceLink(
        cyber_event_id=event.id,
        raw_article_id=article.id,
        match_score=1.0,
        is_primary_source=True,
    )
    db.session.add(link)

    article.processing_status = "clustered"
    db.session.flush()

    event.source_count = EventSourceLink.query.filter_by(
        cyber_event_id=event.id
    ).count()

    db.session.commit()
    return event


def refresh_event(event_id):
    """
    Minimal placeholder for event refresh.
    """
    return True