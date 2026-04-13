import atexit
import logging
from datetime import datetime, UTC

from apscheduler.schedulers.background import BackgroundScheduler

from app.jobs import run_full_pipeline

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

automation_status = {
    "enabled": False,
    "interval_minutes": None,
    "scheduler_running": False,
    "last_run_started_at": None,
    "last_run_finished_at": None,
    "last_run_success": None,
    "last_run_result": None,
    "last_run_error": None,
}


def _utc_now_iso():
    return datetime.now(UTC).isoformat()


def get_automation_status():
    """
    Return current in-memory automation state for debugging/status checks.
    """
    status = dict(automation_status)
    status["scheduler_running"] = scheduler.running
    return status


def _scheduled_pipeline_run(app):
    """
    Run the full pipeline inside an application context and record status.
    """
    automation_status["last_run_started_at"] = _utc_now_iso()
    automation_status["last_run_finished_at"] = None
    automation_status["last_run_success"] = None
    automation_status["last_run_result"] = None
    automation_status["last_run_error"] = None

    try:
        with app.app_context():
            logger.info("Starting scheduled Cyber Signal pipeline run")
            result = run_full_pipeline(force_extract=False)
            logger.info("Completed scheduled Cyber Signal pipeline run: %s", result)

        automation_status["last_run_success"] = True
        automation_status["last_run_result"] = result
    except Exception as exc:
        logger.exception("Scheduled Cyber Signal pipeline run failed")
        automation_status["last_run_success"] = False
        automation_status["last_run_error"] = str(exc)
    finally:
        automation_status["last_run_finished_at"] = _utc_now_iso()


def start_scheduler(app):
    """
    Start the background scheduler if automation is enabled.
    Safe to call once during app startup.
    """
    automation_status["enabled"] = app.config.get("AUTOMATION_ENABLED", False)
    automation_status["interval_minutes"] = app.config.get(
        "AUTOMATION_INTERVAL_MINUTES",
        60,
    )

    if not app.config.get("AUTOMATION_ENABLED", False):
        app.logger.info("Automation scheduler disabled")
        return

    if scheduler.running:
        app.logger.info("Automation scheduler already running")
        return

    interval_minutes = app.config.get("AUTOMATION_INTERVAL_MINUTES", 60)

    scheduler.add_job(
        func=_scheduled_pipeline_run,
        trigger="interval",
        minutes=interval_minutes,
        args=[app],
        id="cyber_signal_pipeline",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))

    automation_status["scheduler_running"] = True

    app.logger.info(
        "Automation scheduler started with %s-minute interval",
        interval_minutes,
    )