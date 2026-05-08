from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy.orm import joinedload, selectinload

from app.models import CyberEvent, EventSourceLink


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
):
    events = get_filtered_events(
        industry=industry,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
    )

    total_incidents = len(events)
    confirmed_incidents = len([e for e in events if e.event_status == "confirmed"])
    emerging_signals = len([e for e in events if e.event_status == "emerging"])

    attack_types = [e.attack_type for e in events if e.attack_type]
    industries = [
        e.industry
        for e in events
        if e.industry and e.industry != "Unknown"
    ]

    return {
        "total_events": total_incidents,
        "confirmed_events": confirmed_incidents,
        "emerging_events": emerging_signals,
        "top_attack_type": _most_common_non_empty(attack_types),
        "top_targeted_industry": _most_common_non_empty(industries),
    }


def build_trends(
    industry=None,
    region=None,
    attack_type=None,
    time_range=None,
):
    """
    Return the lightweight trend snapshot using the active feed filters.
    """
    events = get_filtered_events(
        industry=industry,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
    )

    attack_types = [e.attack_type for e in events if e.attack_type]
    contexts = _event_contexts(events)

    return {
        "top_attack_types": _top_counts(attack_types, limit=5),
        "top_industries": _top_counts(contexts, limit=None),
    }