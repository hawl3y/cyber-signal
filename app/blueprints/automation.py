from datetime import UTC

from flask import Blueprint, jsonify

from app.models import AutomationRun

automation_bp = Blueprint("automation", __name__, url_prefix="/api/automation")


AUTOMATION_INTERVAL_MINUTES = 240


def _isoformat_or_none(value):
    if not value:
        return None
    return value.replace(tzinfo=UTC).isoformat()


def get_latest_automation_run():
    return (
        AutomationRun.query
        .order_by(AutomationRun.started_at.desc())
        .first()
    )


def get_latest_successful_automation_run():
    return (
        AutomationRun.query
        .filter_by(success=True)
        .filter(AutomationRun.finished_at.isnot(None))
        .order_by(AutomationRun.finished_at.desc())
        .first()
    )


@automation_bp.route("/status", methods=["GET"])
def get_automation_debug_status():
    latest_run = get_latest_automation_run()
    latest_successful_run = get_latest_successful_automation_run()

    return jsonify({
        "automation_mode": "render_cron",
        "enabled": True,
        "interval_minutes": AUTOMATION_INTERVAL_MINUTES,
        "last_data_updated_at": (
            _isoformat_or_none(latest_successful_run.finished_at)
            if latest_successful_run
            else None
        ),
        "last_run_started_at": (
            _isoformat_or_none(latest_run.started_at)
            if latest_run
            else None
        ),
        "last_run_finished_at": (
            _isoformat_or_none(latest_run.finished_at)
            if latest_run
            else None
        ),
        "last_run_success": latest_run.success if latest_run else None,
        "last_run_result": latest_run.result if latest_run else None,
        "last_run_error": latest_run.error if latest_run else None,
    })