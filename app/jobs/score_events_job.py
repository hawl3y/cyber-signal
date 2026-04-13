from datetime import datetime, UTC

from app.extensions import db
from app.models import CyberEvent
from app.services.scoring import calculate_confidence


def score_events_job():
    """
    Entry point for confidence scoring stage.
    """
    events = CyberEvent.query.all()

    for event in events:
        score, level = calculate_confidence(event)

        event.confidence_score = score
        event.confidence_level = level
        event.last_confidence_scored_at = datetime.now(UTC)

    db.session.commit()
    return True