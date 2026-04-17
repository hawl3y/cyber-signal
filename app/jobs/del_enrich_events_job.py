from app.models import CyberEvent, EventSourceLink
from app.services.enrichment import (
    get_linked_articles,
    get_extractions,
    aggregate_event_data,
    update_event,
)


def enrich_events_job():
    """
    Entry point for enrichment stage.
    """
    event_ids = [event.id for event in CyberEvent.query.all()]

    for event_id in event_ids:
        linked_articles = get_linked_articles(event_id)
        extractions = get_extractions(event_id)
        source_count = EventSourceLink.query.filter_by(
            cyber_event_id=event_id
        ).count()

        event_data = aggregate_event_data(
            linked_articles,
            extractions,
            source_count,
        )
        update_event(event_id, event_data)

    return True