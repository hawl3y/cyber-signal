from flask import Blueprint, jsonify

from app.automation import get_automation_status

automation_bp = Blueprint("automation", __name__, url_prefix="/api/automation")


@automation_bp.route("/status", methods=["GET"])
def get_automation_debug_status():
    return jsonify(get_automation_status())