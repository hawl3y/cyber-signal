import re

from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink
from app.services.extraction import region_for_country
from app.utils.sources import get_source_config


def _source_weight(source_name):
    """
    Authoritativeness rank used when merging field values from multiple
    linked extractions. Higher = wins ties when the field is non-blank.
    """
    config = get_source_config(source_name) or {}
    source_class = config.get("source_class")
    if source_class == "primary_disclosure":
        return 100
    if source_class in {"official_alert", "exploited_vulnerability"}:
        return 80
    if config.get("tier_trusted_alone"):
        return 80
    if source_class == "incident_news":
        return 50
    return 30


def _ranked_extractions(event_id):
    """
    Return [(article, extraction)] sorted by source weight desc, then
    publication recency desc as a tiebreaker. Used so refresh_event picks
    the most authoritative non-blank value for each event field instead of
    letting the latest article unconditionally overwrite earlier ones.
    """
    links = EventSourceLink.query.filter_by(cyber_event_id=event_id).all()
    ranked = []
    for link in links:
        article = RawArticle.query.get(link.raw_article_id)
        if not article:
            continue
        extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()
        if not extraction:
            continue
        weight = _source_weight(article.source_name)
        rank_time = article.published_at or article.created_at or extraction.created_at
        rank_ts = rank_time.timestamp() if rank_time else 0
        ranked.append((weight, rank_ts, article, extraction))

    ranked.sort(key=lambda row: (-row[0], -row[1]))
    return [(article, extraction) for _, _, article, extraction in ranked]


def _is_blank(value):
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    if value == "Unknown":
        return True
    return False


def _best_field(ranked_pairs, attr):
    """First non-blank value walking the ranked list (highest weight wins)."""
    for _, extraction in ranked_pairs:
        value = getattr(extraction, attr, None)
        if not _is_blank(value):
            return value
    return None


def _extraction_completeness(extraction):
    """Count of key signal fields that are populated (non-blank, non-Unknown)."""
    score = 0
    for attr in ("victim_org_name", "attack_type", "actor_name", "short_event_summary", "country", "industry"):
        if not _is_blank(getattr(extraction, attr, None)):
            score += 1
    return score


def _ranked_extractions_for_content(event_id):
    """
    Like _ranked_extractions but uses extraction completeness as a secondary
    sort key before recency. The article that knows the most wins title/summary
    selection, preventing follow-up articles with fewer extracted fields from
    overwriting richer earlier coverage.
    """
    links = EventSourceLink.query.filter_by(cyber_event_id=event_id).all()
    ranked = []
    for link in links:
        article = RawArticle.query.get(link.raw_article_id)
        if not article:
            continue
        extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()
        if not extraction:
            continue
        weight = _source_weight(article.source_name)
        completeness = _extraction_completeness(extraction)
        rank_time = article.published_at or article.created_at or extraction.created_at
        rank_ts = rank_time.timestamp() if rank_time else 0
        ranked.append((weight, completeness, rank_ts, article, extraction))

    ranked.sort(key=lambda row: (-row[0], -row[1], -row[2]))
    return [(article, extraction) for _, _, _, article, extraction in ranked]


def _is_primary_source_article(article):
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
        # Victim-confirmation language — covers headlines like "Trellix discloses data breach"
        # and summaries like "Mediaworks confirmed the incident on Friday"
        "confirmed the incident",
        "confirmed the breach",
        "confirmed the attack",
        "confirmed the cyberattack",
        "confirmed a breach",
        "confirmed a data breach",
        "disclosed a breach",
        "disclosed a data breach",
        "discloses data breach",
        "discloses a breach",
        "acknowledged the breach",
        "acknowledged the incident",
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


def _is_trusted_alone_source(source_name):
    """A source whose single-article reporting is enough to confirm an event."""
    if not source_name:
        return False
    config = get_source_config(source_name)
    if not config:
        return False
    if config.get("source_class") in {
        "official_alert",
        "exploited_vulnerability",
        "primary_disclosure",
    }:
        return True
    if config.get("tier_trusted_alone"):
        return True
    return False


def _event_has_trusted_alone_source(event):
    return any(
        link.raw_article and _is_trusted_alone_source(link.raw_article.source_name)
        for link in event.event_sources
    )


def _event_has_primary_source_evidence(event):
    return any(link.is_primary_source for link in event.event_sources)


def _max_source_class_score(event):
    best = 0
    for link in event.event_sources:
        if not link.raw_article:
            continue
        config = get_source_config(link.raw_article.source_name) or {}
        source_class = config.get("source_class")
        if source_class == "primary_disclosure":
            best = max(best, 90)
        elif source_class in {"official_alert", "exploited_vulnerability"}:
            best = max(best, 85)
        elif config.get("tier_trusted_alone"):
            best = max(best, 80)
    return best


def _compute_confidence_score(event, source_count, has_primary_evidence):
    """
    Numeric trust score (0-100) derived deterministically from the same
    inputs as event_status. Designed to align with the categorical level:
    high >= 75, medium 50-74, low < 50.
    """
    base = 0

    if source_count == 1:
        base = 25
    elif source_count >= 2:
        base = 75 + min(source_count - 2, 3) * 3

    base = max(base, _max_source_class_score(event))

    if has_primary_evidence:
        base = max(base, 75)

    if event.actor_name and event.event_signal_type == "incident":
        base += 5

    return max(0, min(100, base))


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
    return RawArticle.query.filter_by(processing_status="ready_for_clustering").all()


def get_extraction(article):
    return ArticleExtraction.query.filter_by(raw_article_id=article.id).first()


def find_candidate_events(extraction):
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
    else:
        existing_link.is_primary_source = _is_primary_source_article(article)

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
    slug = f"event-{article.id}"

    existing_event = CyberEvent.query.filter_by(slug=slug).first()
    if existing_event:
        return existing_event

    seen_at = article.published_at or article.created_at

    victim_org_name = extraction.victim_org_name if extraction else None
    victim_org_normalized = extraction.victim_org_normalized if extraction else None
    victim_display_label = extraction.victim_display_label if extraction else None
    victim_entity_type = extraction.victim_entity_type if extraction else None
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
        victim_display_label=victim_display_label,
        victim_entity_type=victim_entity_type,
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
    event = CyberEvent.query.get(event_id)
    if not event:
        return False

    source_count = EventSourceLink.query.filter_by(
        cyber_event_id=event.id
    ).count()

    event.source_count = source_count

    ranked = _ranked_extractions(event.id)
    content_ranked = _ranked_extractions_for_content(event.id)
    article, extraction = _latest_linked_extraction(event.id)

    def _apply(attr, value):
        """Set when the merge produced a value; otherwise leave the existing
        event field intact so we don't clobber prior AI-enriched data
        (CLAUDE.md: 'Never overwrite enriched data')."""
        if value is not None and not (isinstance(value, str) and not value.strip()):
            setattr(event, attr, value)

    if ranked:
        # Source-weighted merge: highest-weight non-blank value wins per
        # field, so a Krebs/SEC value isn't overwritten by a later, weaker
        # aggregator article. Blank-everywhere fields preserve whatever the
        # event already has.
        # victim fields are always derived from extraction — never AI-enriched.
        # Set directly so that None from extraction can clear stale values.
        event.victim_org_name = _best_field(ranked, "victim_org_name")
        event.victim_org_normalized = _best_field(ranked, "victim_org_normalized")
        event.victim_display_label = _best_field(ranked, "victim_display_label")

        _apply("victim_entity_type", _best_field(ranked, "victim_entity_type"))

        # CVE IDs are clustering anchors, not display entities. Clear them from
        # both the display label (old extraction stored CVE strings there) and
        # victim_org_name.
        _cve_re = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
        if event.victim_display_label and _cve_re.match(event.victim_display_label):
            event.victim_display_label = None
        if event.victim_org_name and _cve_re.match(event.victim_org_name):
            event.victim_org_name = None
            event.victim_org_normalized = None
        # Industry is deterministic (rule-based), not AI-enriched — always update
        # so stale values are cleared when extraction logic changes.
        event.industry = _best_field(ranked, "industry") or "Unknown"
        _apply("attack_type", _best_field(ranked, "attack_type"))
        _apply("country", _best_field(ranked, "country"))

        # Region is a deterministic lookup from country whenever country is
        # set. Avoids variance ('Asia-Pacific' vs 'Asia', US-state-as-country
        # bugs). Only when no country is known do we fall back to whatever
        # the extractions say.
        if event.country:
            derived = region_for_country(event.country)
            if derived:
                event.region = derived
        else:
            _apply("region", _best_field(ranked, "region"))

        if event.victim_org_name:
            _apply("actor_name", _best_field(ranked, "actor_name"))
            _apply("actor_type", _best_field(ranked, "actor_type"))
            _apply("attribution_status", _best_field(ranked, "attribution_status"))
        else:
            event.actor_name = None
            event.actor_type = None
            event.attribution_status = None

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

        if event.event_signal_type == "activity":
            event.victim_org_name = None
            event.victim_org_normalized = None
            event.actor_name = None
            event.actor_type = None
            event.attribution_status = None

        # Title and summary use completeness-weighted ranking: the article that
        # knows the most (most key fields populated) wins, so a narrow follow-up
        # article doesn't overwrite richer earlier coverage.
        best_article = content_ranked[0][0] if content_ranked else None
        if best_article and best_article.title:
            event.canonical_title = best_article.title

        _apply("summary_short", _best_field(content_ranked, "short_event_summary"))

    if article:
        seen_at = article.published_at or article.created_at
        if event.first_seen_at is None:
            event.first_seen_at = seen_at
        if seen_at and (event.last_seen_at is None or seen_at > event.last_seen_at):
            event.last_seen_at = seen_at

    has_trusted_alone = _event_has_trusted_alone_source(event)
    has_primary_evidence = _event_has_primary_source_evidence(event)

    if source_count >= 2:
        event.event_status = "confirmed"
        event.confidence_level = "high"
    elif source_count == 1 and has_trusted_alone:
        event.event_status = "confirmed"
        event.confidence_level = "high"
    elif source_count == 1 and has_primary_evidence:
        event.event_status = "confirmed"
        event.confidence_level = "medium"
    elif source_count == 1:
        event.event_status = "emerging"
        event.confidence_level = "low"
    else:
        event.event_status = "emerging"
        event.confidence_level = None

    event.confidence_score = _compute_confidence_score(
        event, source_count, has_primary_evidence
    )

    text = f"{(event.canonical_title or '').lower()} {(event.summary_short or '').lower()}"

    high_impact_terms = [
        "mass-exploited",
        "mass exploited",
        "actively exploited",
        "widespread",
        "large-scale",
        "millions",
        "critical infrastructure",
        "data breach",
        "wiper",
    ]

    activity_high_impact_terms = [
        "mass-exploited",
        "mass exploited",
        "actively exploited",
        "known exploited vulnerability",
        "critical infrastructure",
    ]

    if event.event_signal_type == "activity":
        event.is_high_impact = any(term in text for term in activity_high_impact_terms)
    else:
        event.is_high_impact = bool(
            event.actor_name
            or any(term in text for term in high_impact_terms)
            or event.attack_type in {"Ransomware", "Data Breach", "Malware"}
        )

    db.session.commit()
    return True