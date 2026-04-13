from app.jobs.ingest_job import scheduled_ingest_job
from app.jobs.process_articles_job import process_articles_job
from app.jobs.extract_signals_job import extract_signals_job
from app.jobs.cluster_events_job import cluster_events_job
from app.jobs.enrich_events_job import enrich_events_job
from app.jobs.score_events_job import score_events_job


def run_full_pipeline(force_extract=False):
    """
    Run the full Cyber Signal pipeline in the correct order.

    This is the canonical orchestration entry point for automation.
    Keep it synchronous and explicit first; scheduling can call this later.
    """
    results = {
        "ingest": False,
        "process": False,
        "extract": False,
        "cluster": False,
        "enrich": False,
        "score": False,
    }

    results["ingest"] = scheduled_ingest_job()
    results["process"] = process_articles_job()
    results["extract"] = extract_signals_job(force=force_extract)
    results["cluster"] = cluster_events_job()
    results["enrich"] = enrich_events_job()
    results["score"] = score_events_job()

    return results