from app.models import CyberEvent


def evaluate_source_count(event):
    """
    Reward corroboration, but cap the contribution.
    """
    source_count = event.source_count or 0

    if source_count >= 5:
        return 5
    if source_count >= 3:
        return 4
    if source_count >= 2:
        return 3
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

    if event.impact_type:
        score += 1

    if event.industry:
        score += 1

    if event.country or event.region:
        score += 1

    if event.victim_org_name:
        score += 1

    if event.primary_cve_id or (
        event.vuln_status and event.vuln_status.lower() == "known_vulnerability"
    ):
        score += 1

    if event.actor_name:
        score += 1

    return score


def evaluate_uncertainty(event):
    """
    Penalize missing or weakly resolved fields.
    """
    penalty = 0

    if not event.attack_type or event.attack_type == "Unknown":
        penalty += 2

    if not event.impact_type:
        penalty += 1

    if not event.industry:
        penalty += 1

    if not event.country and not event.region:
        penalty += 1

    if not event.victim_org_name:
        penalty += 1

    if event.access_vector == "Unknown Initial Access":
        penalty += 1

    return penalty


def map_score_to_level(score):
    if score >= 9:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


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