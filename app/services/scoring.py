from app.models import CyberEvent


def evaluate_source_count(event):
    return min(event.source_count or 0, 10)


def evaluate_source_quality(event):
    return event.high_credibility_source_count or 0


def evaluate_signal_strength(event):
    return 1 if event.attack_type else 0


def evaluate_uncertainty(event):
    return 0


def map_score_to_level(score):
    if score >= 15:
        return "high"
    elif score >= 8:
        return "medium"
    return "low"


def calculate_confidence(event):
    score = 0

    score += evaluate_source_count(event)
    score += evaluate_source_quality(event)
    score += evaluate_signal_strength(event)
    score -= evaluate_uncertainty(event)

    level = map_score_to_level(score)

    return score, level