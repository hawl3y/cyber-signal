from app.models import CyberEvent


def evaluate_source_count(event):
    """
    Reward corroboration, but keep single-source incidents viable.
    """
    source_count = event.source_count or 0

    if source_count >= 5:
        return 4
    if source_count >= 3:
        return 3
    if source_count >= 2:
        return 2
    if source_count >= 1:
        return 1
    return 0


def evaluate_source_quality(event):
    """
    Reward high-credibility coverage separately from raw count.
    """
    high_cred_count = event.high_credibility_source_count or 0

    if high_cred_count >= 3:
        return 4
    if high_cred_count >= 2:
        return 3
    if high_cred_count >= 1:
        return 2
    return 0


def evaluate_signal_strength(event):
    """
    Reward structured completeness for fields that make an event analytically useful.
    """
    score = 0

    if event.attack_type and event.attack_type != "Unknown":
        score += 2

    if event.access_vector and event.access_vector != "Unknown Initial Access":
        score += 1

    if event.impact_type and event.impact_type != "Unknown":
        score += 2

    if event.industry and event.industry != "Other":
        score += 1

    if event.country or event.region:
        score += 1

    if event.victim_org_name:
        score += 2

    if event.primary_cve_id or (
        event.vuln_status and event.vuln_status.lower() == "known_vulnerability"
    ):
        score += 1

    if event.actor_name:
        score += 1

    if (
        event.attack_type in ["Malware", "Data Breach", "Ransomware", "Exploitation"]
        and event.victim_org_name
    ):
        score += 1

    if (
        event.access_vector in ["Web", "Third-Party", "Exploitation", "Credential Abuse", "Phishing"]
        and event.impact_type
    ):
        score += 1

    return score


def evaluate_uncertainty(event):
    """
    Penalize missing or weakly resolved fields, but do not over-penalize
    valid single-source incidents with incomplete enrichment.
    """
    penalty = 0

    if not event.attack_type or event.attack_type == "Unknown":
        penalty += 2

    if not event.impact_type or event.impact_type == "Unknown":
        penalty += 1

    if not event.industry or event.industry == "Other":
        penalty += 1

    if not event.country and not event.region:
        penalty += 1

    if not event.victim_org_name:
        penalty += 2

    if event.access_vector == "Unknown Initial Access":
        penalty += 1

    return penalty


def map_score_to_level(score):
    if score >= 10:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def derive_verification_level(event, confidence_level):
    """
    Product-facing verification level.

    This is related to confidence, but leans more heavily on corroboration.
    Historical curated records retain high verification by default.
    """
    source_count = event.source_count or 0
    high_cred_count = event.high_credibility_source_count or 0

    if event.record_origin == "historical_dataset":
        return "high"

    if confidence_level == "high" and (source_count >= 2 or high_cred_count >= 1):
        return "high"

    if confidence_level in ["medium", "high"]:
        return "medium"

    return "low"


def derive_is_high_impact(event, confidence_level):
    """
    Flag events that are especially meaningful from an impact perspective.
    """
    if event.impact_type in ["Operational Disruption", "Financial Loss", "Extortion"]:
        return True

    if event.attack_type == "Ransomware":
        return True

    if event.zero_day_flag:
        return True

    if (
        event.attack_type == "Data Breach"
        and event.victim_org_name
        and confidence_level in ["medium", "high"]
    ):
        return True

    if (
        event.attack_type == "Malware"
        and event.victim_org_name
        and event.access_vector in ["Web", "Third-Party"]
        and confidence_level == "high"
    ):
        return True

    return False


def derive_event_status(event, confidence_level, verification_level):
    """
    Lifecycle mapping for live-detected events.

    Status intent:
    - historical: curated historical dataset record
    - candidate: early or weakly resolved signal
    - active: developing event with some corroboration or medium confidence
    - enriched: structurally well-defined event, but not fully confirmed
    - confirmed: highly corroborated / trusted event
    """
    source_count = event.source_count or 0
    high_cred_count = event.high_credibility_source_count or 0

    if event.record_origin == "historical_dataset":
        return "historical"

    if verification_level == "high" and (source_count >= 2 or high_cred_count >= 1):
        return "confirmed"

    if (
        event.victim_org_name
        and event.impact_type
        and event.attack_type
        and event.attack_type != "Unknown"
        and confidence_level in ["medium", "high"]
        and verification_level in ["medium", "high"]
    ):
        return "enriched"

    if source_count >= 2 or verification_level == "medium" or confidence_level == "medium":
        return "active"

    return "candidate"


def calculate_confidence(event):
    score = 0

    score += evaluate_source_count(event)
    score += evaluate_source_quality(event)
    score += evaluate_signal_strength(event)
    score -= evaluate_uncertainty(event)

    if score < 0:
        score = 0

    level = map_score_to_level(score)

    return score, level