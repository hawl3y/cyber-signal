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
    # placeholder: in future we will iterate over events
    event_ids = []

    for event_id in event_ids:
        linked_articles = get_linked_articles(event_id)
        extractions = get_extractions(event_id)

        event_data = aggregate_event_data(linked_articles, extractions)
        update_event(event_id, event_data)

    return True