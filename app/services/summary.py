from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy.orm import joinedload, selectinload

from app.models import CyberEvent, EventSourceLink
from app.utils.sources import get_source_config


def get_event_reference_time(event):
    """
    Return the best available timestamp for sorting and filtering live MVP events.
    """
    return event.last_seen_at or event.first_seen_at or event.updated_at or event.created_at


def get_filtered_events(
    industry=None,
    region=None,
    attack_type=None,
    time_range=None,
    signal_type=None,
    high_impact=None,
    high_trust=None,
):
    """
    Return live events filtered by the MVP's minimal structured fields.
    """
    query = CyberEvent.query.options(
        selectinload(CyberEvent.event_sources).joinedload(EventSourceLink.raw_article)
    )

    if industry:
        query = query.filter(CyberEvent.industry.ilike(industry))

    if region:
        query = query.filter(CyberEvent.region.ilike(region))

    if attack_type:
        query = query.filter(CyberEvent.attack_type.ilike(attack_type))

    if signal_type:
        query = query.filter(CyberEvent.event_signal_type == signal_type)

    if high_impact:
        query = query.filter(CyberEvent.is_high_impact == True)  # noqa: E712

    if high_trust:
        query = query.filter(CyberEvent.confidence_score >= 75)

    events = query.all()

    if time_range:
        now = datetime.utcnow()

        if time_range == "24h":
            cutoff = now - timedelta(hours=24)
        elif time_range == "7d":
            cutoff = now - timedelta(days=7)
        elif time_range == "30d":
            cutoff = now - timedelta(days=30)
        elif time_range == "90d":
            cutoff = now - timedelta(days=90)
        else:
            cutoff = None

        if cutoff is not None:
            events = [
                event for event in events
                if get_event_reference_time(event)
                and get_event_reference_time(event) >= cutoff
            ]

    return events


def _is_unknown_or_other(value):
    return (value or "").strip().lower() in {"unknown", "other"}


def _most_common_non_empty(values):
    cleaned = [value.strip() for value in values if value and value.strip()]

    if not cleaned:
        return None

    counts = Counter(cleaned)
    known = {
        label: count
        for label, count in counts.items()
        if not _is_unknown_or_other(label)
    }

    if known:
        ordered_known = sorted(
            known.items(),
            key=lambda item: (-item[1], item[0].lower()),
        )
        return ordered_known[0][0]

    return "Unknown"


def _top_counts(values, limit=5):
    cleaned = [value.strip() for value in values if value and value.strip()]

    counts = Counter(cleaned)

    if not counts:
        return []

    known = {
        label: count
        for label, count in counts.items()
        if not _is_unknown_or_other(label)
    }
    unknown = {
        label: count
        for label, count in counts.items()
        if _is_unknown_or_other(label)
    }

    ordered = sorted(
        known.items(),
        key=lambda item: (-item[1], item[0].lower()),
    )

    if unknown:
        ordered += sorted(
            unknown.items(),
            key=lambda item: (-item[1], item[0].lower()),
        )

    if limit is not None:
        ordered = ordered[:limit]

    return [
        {"label": label, "count": count}
        for label, count in ordered
    ]


def _event_context(event):
    if event.victim_entity_type == "vulnerability":
        return "Vulnerability"

    if event.victim_entity_type == "product_or_platform":
        return "Product / Platform"

    if event.event_signal_type == "activity":
        return "Security Activity"

    if event.industry and event.industry != "Unknown":
        return event.industry

    return "Other"


def _event_contexts(events):
    return [
        context
        for event in events
        if (context := _event_context(event))
    ]


def build_summary(
    industry=None,
    region=None,
    attack_type=None,
    time_range=None,
    signal_type=None,
):
    events = get_filtered_events(
        industry=industry,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
        signal_type=signal_type,
    )

    total_events = len(events)
    confirmed_events = sum(1 for e in events if e.event_status == "confirmed")
    emerging_events = sum(1 for e in events if e.event_status == "emerging")
    high_trust_events = sum(
        1 for e in events
        if e.confidence_score is not None and e.confidence_score >= 75
    )
    high_impact_events = sum(1 for e in events if e.is_high_impact)

    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    new_today_events = sum(
        1 for e in events
        if (ref := get_event_reference_time(e)) and ref >= cutoff_24h
    )

    attack_types = [e.attack_type for e in events if e.attack_type]
    industries = [
        e.industry
        for e in events
        if e.industry and e.industry != "Unknown"
    ]

    return {
        "total_events": total_events,
        "high_trust_events": high_trust_events,
        "high_impact_events": high_impact_events,
        "new_today_events": new_today_events,
        # Legacy fields kept for API stability — no longer rendered in cards
        "confirmed_events": confirmed_events,
        "emerging_events": emerging_events,
        "top_attack_type": _most_common_non_empty(attack_types),
        "top_targeted_industry": _most_common_non_empty(industries),
    }


def build_trends(
    industry=None,
    region=None,
    attack_type=None,
    time_range=None,
    signal_type=None,
):
    """
    Trend snapshot for the triage view. Three direction-driven blocks instead
    of static top-N counts: what's rising, who's active, where coverage is
    coming from. Industry/region facet filters apply; attack_type and
    time_range are intentionally ignored on the first two blocks because
    those operate on their own 7d/14d windows.
    """
    now = datetime.utcnow()
    cutoff_7d = now - timedelta(days=7)
    cutoff_14d = now - timedelta(days=14)

    # Use a window-agnostic event set for the rolling-window calculations,
    # respecting only the geographic/industry/signal context.
    rolling_events = get_filtered_events(
        industry=industry,
        region=region,
        signal_type=signal_type,
        time_range=None,
    )

    last_7d = []
    prev_7d = []
    for event in rolling_events:
        ref = get_event_reference_time(event)
        if not ref:
            continue
        if ref >= cutoff_7d:
            last_7d.append(event)
        elif ref >= cutoff_14d:
            prev_7d.append(event)

    current_counts = Counter(
        e.attack_type for e in last_7d if e.attack_type and not _is_unknown_or_other(e.attack_type)
    )
    previous_counts = Counter(
        e.attack_type for e in prev_7d if e.attack_type and not _is_unknown_or_other(e.attack_type)
    )

    rising = []
    for label, current in current_counts.items():
        previous = previous_counts.get(label, 0)
        rising.append({
            "label": label,
            "current": current,
            "previous": previous,
            "delta": current - previous,
            "is_new": previous == 0,
        })
    # Rank by largest weekly increase, then by absolute volume as a tiebreaker.
    rising.sort(key=lambda x: (-x["delta"], -x["current"], x["label"].lower()))
    rising = rising[:5]

    actor_counts = Counter(
        e.actor_name for e in last_7d
        if e.actor_name and not _is_unknown_or_other(e.actor_name)
    )
    active_actors = [
        {"label": label, "count": count}
        for label, count in actor_counts.most_common(5)
    ]

    # Top sources reflect the user's currently filtered view (full filter set
    # applies) — this is the "is the feed dominated by one outlet?" question.
    filtered_events = get_filtered_events(
        industry=industry,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
        signal_type=signal_type,
    )
    source_counts = Counter()
    for event in filtered_events:
        seen = set()
        for link in event.event_sources:
            article = link.raw_article
            if not article:
                continue
            config = get_source_config(article.source_name) or {}
            label = (
                config.get("display_label")
                or article.publisher
                or article.source_name
            )
            if label:
                seen.add(label)
        for source in seen:
            source_counts[source] += 1
    # Show every source contributing to the current view rather than capping.
    # The registry is small (~6 entries) and dropping a high-credibility
    # source like SEC EDGAR off the bottom would distort the coverage signal.
    top_sources = [
        {"label": label, "count": count}
        for label, count in source_counts.most_common()
    ]

    return {
        "rising_attack_types": rising,
        "active_actors": active_actors,
        "top_sources": top_sources,
    }