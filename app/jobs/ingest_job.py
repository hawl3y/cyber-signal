from app.utils.sources import load_active_sources
from app.services.ingestion import fetch_source_items, normalize_article, save_raw_article

def scheduled_ingest_job():
    """
    Entry point for ingestion job.
    """
    sources = load_active_sources()

    for source in sources:
        items = fetch_source_items(source)

        for item in items:
            normalized = normalize_article(item)
            save_raw_article(normalized)

    return True