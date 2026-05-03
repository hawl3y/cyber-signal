from datetime import UTC

from flask import Blueprint, jsonify

from app.automation import get_automation_status
from app.models import AutomationRun

automation_bp = Blueprint("automation", __name__, url_prefix="/api/automation")


def _isoformat_or_none(value):
    if not value:
        return None
    return value.replace(tzinfo=UTC).isoformat()


def get_last_successful_automation_run():
    return (
        AutomationRun.query
        .filter_by(success=True)
        .filter(AutomationRun.finished_at.isnot(None))
        .order_by(AutomationRun.finished_at.desc())
        .first()
    )


@automation_bp.route("/status", methods=["GET"])
def get_automation_debug_status():
    status = get_automation_status()

    latest_run = get_last_successful_automation_run()
    status["last_data_updated_at"] = (
        _isoformat_or_none(latest_run.finished_at)
        if latest_run
        else None
    )

    return jsonify(status)