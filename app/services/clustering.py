from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink
from app.utils.sources import get_source_config


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
    Find candidate events using victim organization only.

    Keep this strict for now to prevent false merges.
    """
    if not extraction:
        return []

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

    return []


def find_best_match(extraction, candidates):
    """
    Return a strict deterministic match result.

    Only allow a match when victim organization aligns exactly.
    """
    class Result:
        def __init__(self, score=0, event_id=None):
            self.score = score
            self.event_id = event_id

    if not extraction or not candidates:
        return Result()

    for candidate in candidates:
        if (
            extraction.victim_org_normalized
            and candidate.victim_org_normalized
            and extraction.victim_org_normalized == candidate.victim_org_normalized
        ):
            return Result(score=1.0, event_id=candidate.id)

        if (
            extraction.victim_org_name
            and candidate.victim_org_name
            and extraction.victim_org_name == candidate.victim_org_name
        ):
            return Result(score=0.95, event_id=candidate.id)

    return Result(score=0, event_id=None)


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

    db.session.commit()
    return existing_link if existing_link else link


def create_event(article, extraction):
    """
    Create a new MVP-style cyber event from article + extraction,
    or return the existing event for this article slug if it already exists.

    This intentionally avoids enrichment-time inference and only uses
    fields directly available from the article and thin extraction layer.
    """
    slug = f"event-{article.id}"

    existing_event = CyberEvent.query.filter_by(slug=slug).first()
    if existing_event:
        return existing_event

    seen_at = article.published_at or article.created_at

    victim_org_name = extraction.victim_org_name if extraction else None
    victim_org_normalized = extraction.victim_org_normalized if extraction else None
    industry = extraction.industry if extraction else None
    attack_type = extraction.attack_type if extraction else None
    country = extraction.country if extraction else None
    region = extraction.region if extraction else None
    summary_short = extraction.short_event_summary if extraction else None

    source_config = get_source_config(article.source_name)
    event_signal_type = (
        source_config.get("signal_kind")
        if source_config and source_config.get("signal_kind") in {"incident", "activity"}
        else "incident"
    )

    event = CyberEvent(
        canonical_title=article.title or "Untitled Event",
        slug=slug,
        event_status="emerging",
        confidence_level="medium",
        record_origin="live_detection",
        victim_org_name=victim_org_name,
        victim_org_normalized=victim_org_normalized,
        industry=industry,
        attack_type=attack_type,
        event_signal_type=event_signal_type,
        country=country,
        region=region,
        summary_short=summary_short,
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

    db.session.commit()
    refresh_event(event.id)
    return event

def _latest_linked_extraction(event_id):
    """
    Return the most recent linked extraction for an event based on article publish
    time first, then article creation time, then extraction creation time.
    """
    links = (
        EventSourceLink.query.filter_by(cyber_event_id=event_id)
        .order_by(EventSourceLink.linked_at.desc())
        .all()
    )

    ranked = []
    for link in links:
        article = RawArticle.query.get(link.raw_article_id)
        if not article:
            continue

        extraction = ArticleExtraction.query.filter_by(
            raw_article_id=article.id
        ).first()

        if not extraction:
            continue

        rank_time = (
            article.published_at
            or article.created_at
            or extraction.created_at
        )

        ranked.append((rank_time, article, extraction))

    ranked.sort(key=lambda item: item[0] or 0, reverse=True)

    if not ranked:
        return None, None

    _, article, extraction = ranked[0]
    return article, extraction

def refresh_event(event_id):
    """
    Refresh an event using MVP rules only.

    This keeps event state deterministic and lightweight:
    - source_count is derived from actual linked evidence
    - status is based on corroboration
    - confidence is based on simple source-count thresholds
    - core display fields are refreshed from the latest linked extraction
    """
    event = CyberEvent.query.get(event_id)
    if not event:
        return False

    source_count = EventSourceLink.query.filter_by(
        cyber_event_id=event.id
    ).count()

    event.source_count = source_count

    article, extraction = _latest_linked_extraction(event.id)

    if extraction:
        if extraction.victim_org_name:
            event.victim_org_name = extraction.victim_org_name
        if extraction.victim_org_normalized:
            event.victim_org_normalized = extraction.victim_org_normalized
        if extraction.industry:
            event.industry = extraction.industry
        if extraction.attack_type:
            event.attack_type = extraction.attack_type
        if extraction.country:
            event.country = extraction.country
        if extraction.region:
            event.region = extraction.region

        # Always treat current pipeline output as incident
        linked_source_names = {
            link.raw_article.source_name
            for link in event.event_sources
            if link.raw_article and link.raw_article.source_name
        }

        signal_types = set()
        for source_name in linked_source_names:
            source_config = get_source_config(source_name)
            if source_config and source_config.get("signal_kind") in {"incident", "activity"}:
                signal_types.add(source_config.get("signal_kind"))

        if "incident" in signal_types:
            event.event_signal_type = "incident"
        elif "activity" in signal_types:
            event.event_signal_type = "activity"
        else:
            event.event_signal_type = "incident"

        if extraction.short_event_summary:
            event.summary_short = extraction.short_event_summary

    if article:
        seen_at = article.published_at or article.created_at
        if event.first_seen_at is None:
            event.first_seen_at = seen_at
        if seen_at and (event.last_seen_at is None or seen_at > event.last_seen_at):
            event.last_seen_at = seen_at

    if source_count >= 2:
        event.event_status = "confirmed"
    else:
        event.event_status = "emerging"

    if source_count >= 2:
        event.confidence_level = "high"
    elif source_count == 1:
        event.confidence_level = "medium"
    else:
        event.confidence_level = None

    db.session.commit()
    return True