from app.services.event_enrichment import enrich_events


def enrich_events_job(force=False, max_workers=5):
    """
    Entry point for the event-level AI enrichment stage. Runs after clustering.
    Returns a stats dict so the pipeline orchestrator can log it.
    """
    return enrich_events(force=force, max_workers=max_workers)
