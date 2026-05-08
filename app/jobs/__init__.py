import time

from app.jobs.ingest_job import scheduled_ingest_job
from app.jobs.process_articles_job import process_articles_job
from app.jobs.extract_signals_job import extract_signals_job
from app.jobs.cluster_events_job import cluster_events_job
from app.jobs.actor_recognition_job import actor_recognition_job


def _run_stage(name, fn, results):
    started = time.monotonic()
    try:
        results[name] = fn()
    finally:
        results[f"{name}_seconds"] = round(time.monotonic() - started, 2)


def run_full_pipeline(force_extract=False):
    """
    Run the MVP live pipeline in the correct order.

    Stages: ingest -> process -> extract -> cluster -> attribute.
    Per-stage wall-clock is recorded under <stage>_seconds for log surfacing.
    """
    results = {
        "ingest": False,
        "process": False,
        "extract": False,
        "cluster": False,
        "attribute": None,
    }

    _run_stage("ingest", scheduled_ingest_job, results)
    _run_stage("process", process_articles_job, results)
    _run_stage("extract", lambda: extract_signals_job(force=force_extract), results)
    _run_stage("cluster", cluster_events_job, results)
    _run_stage("attribute", actor_recognition_job, results)

    return results
