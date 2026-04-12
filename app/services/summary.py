from app.models import CyberEvent


def get_filtered_events():
    """
    Placeholder for filtering logic.
    """
    return CyberEvent.query.all()


def build_summary():
    events = get_filtered_events()

    total_events = len(events)

    industries = [e.industry for e in events if e.industry]
    attack_types = [e.attack_type for e in events if e.attack_type]

    top_industry = max(set(industries), key=industries.count) if industries else None
    top_attack_type = max(set(attack_types), key=attack_types.count) if attack_types else None

    known_vuln_events = [e for e in events if e.primary_cve_id]
    known_vuln_percent = (
        (len(known_vuln_events) / total_events) * 100 if total_events else 0
    )

    return {
        "total_events": total_events,
        "top_industry": top_industry,
        "top_attack_type": top_attack_type,
        "known_vuln_percent": known_vuln_percent,
    }


def build_map():
    events = get_filtered_events()

    return [
        {
            "lat": e.latitude,
            "lng": e.longitude,
            "title": e.canonical_title,
        }
        for e in events
        if e.latitude and e.longitude
    ]