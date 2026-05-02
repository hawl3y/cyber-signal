import re 

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

def _extract_org_acronym(value):
    if not value:
        return None

    match = re.search(r"\(([A-Z0-9&.-]{2,})\)", value)
    if match:
        return match.group(1)

    uppercase_tokens = re.findall(r"\b[A-Z][A-Z0-9&.-]{1,}\b", value)
    if len(uppercase_tokens) == 1:
        return uppercase_tokens[0]

    return None


def _country_matches(extraction, candidate):
    if not extraction or not candidate:
        return False

    if not extraction.country or not candidate.country:
        return False

    return extraction.country == candidate.country


def _attack_type_matches(extraction, candidate):
    if not extraction or not candidate:
        return False

    if not extraction.attack_type or not candidate.attack_type:
        return False

    return extraction.attack_type == candidate.attack_type


def _acronym_alias_matches(extraction, candidate):
    if not extraction or not candidate:
        return False

    extraction_acronym = _extract_org_acronym(extraction.victim_org_name)
    candidate_acronym = _extract_org_acronym(candidate.victim_org_name)

    if not extraction_acronym or not candidate_acronym:
        return False

    if extraction_acronym != candidate_acronym:
        return False

    if not _country_matches(extraction, candidate):
        return False

    if not _attack_type_matches(extraction, candidate):
        return False

    return True


def _extract_org_acronym(value):
    if not value:
        return None

    match = re.search(r"\(([A-Z0-9&.-]{2,})\)", value)
    if match:
        return match.group(1)

    uppercase_tokens = re.findall(r"\b[A-Z][A-Z0-9&.-]{1,}\b", value)
    if len(uppercase_tokens) == 1:
        return uppercase_tokens[0]

    return None


def _country_matches(extraction, candidate):
    if not extraction or not candidate:
        return False

    if not extraction.country or not candidate.country:
        return False

    return extraction.country == candidate.country


def _attack_type_matches(extraction, candidate):
    if not extraction or not candidate:
        return False

    if not extraction.attack_type or not candidate.attack_type:
        return False

    return extraction.attack_type == candidate.attack_type


def _acronym_alias_matches(extraction, candidate):
    if not extraction or not candidate:
        return False

    extraction_acronym = _extract_org_acronym(extraction.victim_org_name)
    candidate_acronym = _extract_org_acronym(candidate.victim_org_name)

    if not extraction_acronym or not candidate_acronym:
        return False

    if extraction_acronym != candidate_acronym:
        return False

    if not _country_matches(extraction, candidate):
        return False

    if not _attack_type_matches(extraction, candidate):
        return False

    return True


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
    Find candidate events using exact victim matches first, but do not stop there.

    We include narrowed fallback candidates as well so forced reconciliation can
    detect alias cases like different full names sharing the same acronym.
    """
    if not extraction:
        return []

    candidates_by_id = {}

    if extraction.victim_org_normalized:
        exact_normalized = CyberEvent.query.filter_by(
            victim_org_normalized=extraction.victim_org_normalized
        ).all()
        for candidate in exact_normalized:
            candidates_by_id[candidate.id] = candidate

    if extraction.victim_org_name:
        exact_name = CyberEvent.query.filter_by(
            victim_org_name=extraction.victim_org_name
        ).all()
        for candidate in exact_name:
            candidates_by_id[candidate.id] = candidate

    narrowed = CyberEvent.query

    if extraction.country:
        narrowed = narrowed.filter_by(country=extraction.country)

    if extraction.attack_type:
        narrowed = narrowed.filter_by(attack_type=extraction.attack_type)

    for candidate in narrowed.all():
        candidates_by_id[candidate.id] = candidate

    return list(candidates_by_id.values())


def find_best_match(extraction, candidates):
    """
    Return a deterministic match result.

    Match order:
    1. exact normalized victim match
    2. exact victim display-name match
    3. acronym-based alias match with country + attack-type guardrails
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

    for candidate in candidates:
        if (
            extraction.victim_org_name
            and candidate.victim_org_name
            and extraction.victim_org_name == candidate.victim_org_name
        ):
            return Result(score=0.95, event_id=candidate.id)

    for candidate in candidates:
        if _acronym_alias_matches(extraction, candidate):
            return Result(score=0.9, event_id=candidate.id)

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

        if article and article.title:
            event.canonical_title = article.title

        if extraction.short_event_summary:
            event.summary_short = extraction.short_event_summary

    if article:
        seen_at = article.published_at or article.created_at
        if event.first_seen_at is None:
            event.first_seen_at = seen_at
        if seen_at and (event.last_seen_at is None or seen_at > event.last_seen_at):
            event.last_seen_at = seen_at

    single_source_confirmed_incident = False

    if (
        source_count == 1
        and event.event_signal_type == "incident"
        and event.victim_org_name
        and article
    ):
        incident_text = " ".join(
            [
                (article.title or "").strip(),
                (article.summary or "").strip(),
                (article.content or "").strip(),
            ]
        ).lower()

        strong_completed_incident_terms = [
            "data breach",
            "security breach",
            "breached",
            "was breached",
            "was hacked",
            "was compromised",
            "confirmed a breach",
            "confirmed a cyberattack",
            "confirmed a ransomware attack",
            "disclosed a breach",
            "reported a breach",
            "forced offline",
            "taken offline",
            "operational disruption",
            "service disruption",
            "extortion",
            "data-wiping attack",
            "wiper attack",
        ]

        if any(term in incident_text for term in strong_completed_incident_terms):
            single_source_confirmed_incident = True

    if source_count >= 2:
        event.event_status = "confirmed"
        event.confidence_level = "high"
    elif source_count == 1:
        if event.event_signal_type == "activity":
            event.event_status = "emerging"
            event.confidence_level = "medium"
        elif single_source_confirmed_incident:
            event.event_status = "confirmed"
            event.confidence_level = "medium"
        else:
            event.event_status = "emerging"
            event.confidence_level = "medium"
    else:
        event.event_status = "emerging"
        event.confidence_level = None

    db.session.commit()
    return True