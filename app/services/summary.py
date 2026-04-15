from collections import Counter
from datetime import datetime, timedelta, UTC

from app.models import CyberEvent

def get_event_reference_time(event):
    """
    Return the best-known event date for filtering and sorting.

    Priority:
    1. event_occurred_at for historical and hybrid records
    2. last_seen_at
    3. first_seen_at
    4. updated_at
    5. created_at
    """
    if event.record_origin in ["historical_dataset", "hybrid"] and event.event_occurred_at:
        return event.event_occurred_at

    return event.last_seen_at or event.first_seen_at or event.updated_at or event.created_at

def get_filtered_events(
    industry=None,
    country=None,
    region=None,
    attack_type=None,
    time_range=None,
    start_date=None,
    end_date=None,
    record_origin=None,
):
    """
    Return events filtered by optional structured fields.
    """
    query = CyberEvent.query

    if industry:
        query = query.filter(CyberEvent.industry.ilike(industry))

    if country:
        query = query.filter(CyberEvent.country.ilike(country))

    if region:
        query = query.filter(CyberEvent.region.ilike(region))

    if attack_type:
        query = query.filter(CyberEvent.attack_type.ilike(attack_type))

    if record_origin:
        query = query.filter(CyberEvent.record_origin == record_origin)

    if start_date or end_date:
        events = query.all()

        parsed_start = None
        parsed_end = None

        if start_date:
            parsed_start = datetime.fromisoformat(start_date)

        if end_date:
            parsed_end = datetime.fromisoformat(end_date) + timedelta(days=1)

        filtered = []
        for event in events:
            reference_time = get_event_reference_time(event)
            if not reference_time:
                continue

            if parsed_start and reference_time < parsed_start:
                continue

            if parsed_end and reference_time >= parsed_end:
                continue

            filtered.append(event)

        return filtered

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
        elif time_range == "1y":
            cutoff = now - timedelta(days=365)
        else:
            cutoff = None

        if cutoff is not None:
            events = query.all()

            return [
                event for event in events
                if get_event_reference_time(event) and get_event_reference_time(event) >= cutoff
            ]

    return query.all()


def _most_common_non_empty(values):
    cleaned = [value for value in values if value]
    if not cleaned:
        return None

    return Counter(cleaned).most_common(1)[0][0]


def build_summary(
    industry=None,
    country=None,
    region=None,
    attack_type=None,
    time_range=None,
    start_date=None,
    end_date=None,
):
    events = get_filtered_events(
        industry=industry,
        country=country,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
    )

    total_events = len(events)

    industries = [e.industry for e in events if e.industry]
    attack_types = [e.attack_type for e in events if e.attack_type]
    countries = [e.country for e in events if e.country]
    regions = [e.region for e in events if e.region]
    statuses = [e.event_status for e in events if e.event_status]
    verification_levels = [e.verification_level for e in events if e.verification_level]
    origins = [e.record_origin for e in events if e.record_origin]

    top_industry = _most_common_non_empty(industries)
    top_attack_type = _most_common_non_empty(attack_types)
    top_country = _most_common_non_empty(countries)
    top_region = _most_common_non_empty(regions)
    top_event_status = _most_common_non_empty(statuses)
    top_verification_level = _most_common_non_empty(verification_levels)
    top_record_origin = _most_common_non_empty(origins)

    high_impact_events = len(
        [
            e for e in events
            if e.is_high_impact
        ]
    )

    validated_events = len(
        [
            e for e in events
            if e.record_origin == "historical_dataset"
            or e.event_status in ["confirmed", "enriched", "resolved", "historical"]
        ]
    )

    enriched_events = len(
        [
            e for e in events
            if e.event_status == "enriched"
        ]
    )

    historical_events = len(
        [
            e for e in events
            if e.record_origin == "historical_dataset"
        ]
    )

    hybrid_events = len(
        [
            e for e in events
            if e.record_origin == "hybrid"
        ]
    )

    mapped_event_count = len(
        [
            e for e in events
            if e.latitude is not None and e.longitude is not None
        ]
    )

    return {
        "total_events": total_events,
        "mapped_event_count": mapped_event_count,
        "top_industry": top_industry,
        "top_attack_type": top_attack_type,
        "top_country": top_country,
        "top_region": top_region,
        "top_event_status": top_event_status,
        "top_verification_level": top_verification_level,
        "top_record_origin": top_record_origin,
        "high_impact_events": high_impact_events,
        "validated_events": validated_events,
        "enriched_events": enriched_events,
        "historical_events": historical_events,
        "hybrid_events": hybrid_events,
    }


def build_map(
    industry=None,
    country=None,
    region=None,
    attack_type=None,
    time_range=None,
    start_date=None,
    end_date=None,
):
    events = get_filtered_events(
        industry=industry,
        country=country,
        region=region,
        attack_type=attack_type,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
    )

    return [
        {
            "event_id": e.id,
            "lat": e.latitude,
            "lng": e.longitude,
            "title": e.canonical_title,
            "industry": e.industry,
            "country": e.country,
            "region": e.region,
            "attack_type": e.attack_type,
            "event_status": e.event_status,
            "verification_level": e.verification_level,
            "confidence_level": e.confidence_level,
            "is_high_impact": e.is_high_impact,
            "source_count": e.source_count,
        }
        for e in events
        if e.latitude is not None and e.longitude is not None
    ]