from app.utils.sources import load_active_sources
from app.services.ingestion import fetch_source_items, save_raw_article


def scheduled_ingest_job():
    """
    Entry point for ingestion job.
    """
    sources = load_active_sources()

    for source in sources:
        items = fetch_source_items(source)

        for item in items:
            save_raw_article(item)

    return True