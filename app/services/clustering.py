from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink


def _is_primary_source_article(article):
    """
    Lightweight evidence-role classification.

    Primary source means the article appears to contain direct disclosure
    or first-hand reporting from the victim, regulator, or official body.
    """
    if not article:
        return False

    text = " ".join(
        [
            (article.title or "").strip(),
            (article.summary or "").strip(),
            (article.content or "").strip(),
        ]
    ).lower()

    primary_signals = [
        "the company said",
        "the company announced",
        "the organization said",
        "the victim said",
        "according to the company",
        "according to the organization",
        "the regulator said",
        "the sec said",
        "the sec filing",
        "in a filing",
        "in a statement",
        "in a statement shared",
        "official statement",
        "official disclosure",
        "company statement",
        "company disclosed",
        "the hospital said",
        "the vendor said",
        "the provider said",
        "confirmed in a statement",
        "announced that hackers breached its systems",
    ]

    return any(signal in text for signal in primary_signals)


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
    Find candidate events using normalized victim organization as the primary key,
    then raw victim name, then a narrow actor fallback.

    This now supports matching live detections onto historical records so they
    can evolve into hybrid canonical events.
    """
    if not extraction:
        return []

    candidates = []

    if extraction.victim_org_normalized:
        candidates = CyberEvent.query.filter_by(
            victim_org_normalized=extraction.victim_org_normalized
        ).all()
        if candidates:
            return candidates

    if extraction.victim_org_name:
        candidates = CyberEvent.query.filter_by(
            victim_org_name=extraction.victim_org_name
        ).all()
        if candidates:
            return candidates

    if extraction.actor_name:
        candidates = CyberEvent.query.filter_by(
            actor_name=extraction.actor_name
        ).all()
        if candidates:
            return candidates

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

    If a live article attaches to a historical event, promote the record origin
    to hybrid.
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
            is_primary_source=_is_primary_source_article(article),
        )
        db.session.add(link)

    article.processing_status = "clustered"
    db.session.flush()

    event.source_count = EventSourceLink.query.filter_by(
        cyber_event_id=event.id
    ).count()

    seen_at = article.published_at or article.created_at

    if event.first_seen_at is None:
        event.first_seen_at = seen_at

    if seen_at and (event.last_seen_at is None or seen_at > event.last_seen_at):
        event.last_seen_at = seen_at

    if event.record_origin == "historical_dataset":
        event.record_origin = "hybrid"

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

    seen_at = article.published_at or article.created_at

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
        source_count=0,
        first_seen_at=seen_at,
        last_seen_at=seen_at,
    )

    db.session.add(event)
    db.session.flush()

    link = EventSourceLink(
        cyber_event_id=event.id,
        raw_article_id=article.id,
        match_score=1.0,
        is_primary_source=_is_primary_source_article(article),
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