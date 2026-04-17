from app.jobs.ingest_job import scheduled_ingest_job
from app.jobs.process_articles_job import process_articles_job
from app.jobs.extract_signals_job import extract_signals_job
from app.jobs.cluster_events_job import cluster_events_job


def run_full_pipeline(force_extract=False):
    """
    Run the MVP live pipeline in the correct order.

    This intentionally stops after clustering so events reflect the
    simplified live incident model rather than the prior enrichment/scoring flow.
    """
    results = {
        "ingest": False,
        "process": False,
        "extract": False,
        "cluster": False,
    }

    results["ingest"] = scheduled_ingest_job()
    results["process"] = process_articles_job()
    results["extract"] = extract_signals_job(force=force_extract)
    results["cluster"] = cluster_events_job()

    return results