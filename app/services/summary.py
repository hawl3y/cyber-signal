from collections import Counter
from datetime import datetime, timedelta

from app.models import CyberEvent


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
    query = CyberEvent.query

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
        else:
            cutoff = None

        if cutoff is not None:
            events = [
                event for event in events
                if get_event_reference_time(event) and get_event_reference_time(event) >= cutoff
            ]

    return events


def _most_common_non_empty(values):
    cleaned = [value for value in values if value]
    if not cleaned:
        return None

    return Counter(cleaned).most_common(1)[0][0]


def _top_counts(values, limit=5):
    cleaned = [value for value in values if value]
    counts = Counter(cleaned)
    return [
        {"label": label, "count": count}
        for label, count in counts.most_common(limit)
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
    industries = [e.industry for e in events if e.industry]

    return {
        "total_incidents": total_incidents,
        "confirmed_incidents": confirmed_incidents,
        "emerging_signals": emerging_signals,
        "top_attack_type": _most_common_non_empty(attack_types),
        "top_targeted_industry": _most_common_non_empty(industries),
    }


def build_trends():
    """
    Return the lightweight 7-day trend snapshot for the single-page MVP.
    """
    events = get_filtered_events(time_range="7d")

    attack_types = [e.attack_type for e in events if e.attack_type]
    industries = [e.industry for e in events if e.industry]

    return {
        "top_attack_types": _top_counts(attack_types, limit=5),
        "top_industries": _top_counts(industries, limit=5),
    }