from datetime import datetime, UTC

from app.extensions import db
from app.models import CyberEvent
from app.services.scoring import (
    calculate_confidence,
    derive_event_status,
    derive_is_high_impact,
    derive_verification_level,
)


def score_events_job():
    """
    Entry point for confidence scoring stage.
    """
    events = CyberEvent.query.all()

    for event in events:
        score, confidence_level = calculate_confidence(event)
        verification_level = derive_verification_level(event, confidence_level)
        is_high_impact = derive_is_high_impact(event, confidence_level)

        event.confidence_score = score
        event.confidence_level = confidence_level
        event.verification_level = verification_level
        event.is_high_impact = is_high_impact

        if not event.record_origin:
            event.record_origin = "live_detection"

        # Preserve explicit historical records later if you add them.
        if event.record_origin != "historical_dataset":
            event.event_status = derive_event_status(
                event,
                confidence_level,
                verification_level,
            )

        event.last_confidence_scored_at = datetime.now(UTC)

    db.session.commit()
    return True