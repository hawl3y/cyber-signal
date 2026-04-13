from collections import Counter

from app.models import CyberEvent


def get_filtered_events(
    industry=None,
    country=None,
    region=None,
    city=None,
    attack_type=None,
    event_status=None,
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

    if city:
        query = query.filter(CyberEvent.city.ilike(city))

    if attack_type:
        query = query.filter(CyberEvent.attack_type.ilike(attack_type))

    if event_status:
        query = query.filter(CyberEvent.event_status.ilike(event_status))

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
    city=None,
    attack_type=None,
    event_status=None,
):
    events = get_filtered_events(
        industry=industry,
        country=country,
        region=region,
        city=city,
        attack_type=attack_type,
        event_status=event_status,
    )

    total_events = len(events)

    industries = [e.industry for e in events if e.industry]
    attack_types = [e.attack_type for e in events if e.attack_type]
    countries = [e.country for e in events if e.country]
    regions = [e.region for e in events if e.region]

    top_industry = _most_common_non_empty(industries)
    top_attack_type = _most_common_non_empty(attack_types)
    top_country = _most_common_non_empty(countries)
    top_region = _most_common_non_empty(regions)

    known_vuln_events = [
        e for e in events
        if e.primary_cve_id
        or (e.vuln_status and e.vuln_status.lower() == "known_vulnerability")
    ]
    known_vuln_percent = (
        round((len(known_vuln_events) / total_events) * 100, 2)
        if total_events
        else 0
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
        "known_vuln_percent": known_vuln_percent,
    }


def build_map(
    industry=None,
    country=None,
    region=None,
    city=None,
    attack_type=None,
    event_status=None,
):
    events = get_filtered_events(
        industry=industry,
        country=country,
        region=region,
        city=city,
        attack_type=attack_type,
        event_status=event_status,
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
            "city": e.city,
            "attack_type": e.attack_type,
            "event_status": e.event_status,
            "confidence_level": e.confidence_level,
            "source_count": e.source_count,
        }
        for e in events
        if e.latitude is not None and e.longitude is not None
    ]