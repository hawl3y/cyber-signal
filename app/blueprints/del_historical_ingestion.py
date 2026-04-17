from flask import Blueprint, jsonify, request

from app.jobs.ingest_historical_events_job import (
    ingest_historical_events_job,
    load_historical_seed_records,
)
from app.services.historical_import import load_eurepoc_global_dataset

historical_ingestion_bp = Blueprint(
    "historical_ingestion",
    __name__,
    url_prefix="/api/ingest/historical",
)


@historical_ingestion_bp.route("/", methods=["POST"])
def trigger_historical_ingestion():
    payload = request.get_json(silent=True) or {}
    records = payload.get("records", [])

    if not isinstance(records, list):
        return jsonify({"error": "records must be a list"}), 400

    result = ingest_historical_events_job(records)
    return jsonify(
        {
            "status": "historical ingestion complete",
            **result,
        }
    )


@historical_ingestion_bp.route("/seed", methods=["POST"])
def trigger_historical_seed_ingestion():
    records = load_historical_seed_records()
    result = ingest_historical_events_job(records)

    return jsonify(
        {
            "status": "historical seed ingestion complete",
            "source": "app/data/historical_events_seed.json",
            **result,
        }
    )


@historical_ingestion_bp.route("/eurepoc", methods=["POST"])
def trigger_eurepoc_ingestion():
    payload = request.get_json(silent=True) or {}
    filepath = payload.get("filepath")

    records = load_eurepoc_global_dataset(filepath=filepath)
    result = ingest_historical_events_job(records)

    return jsonify(
        {
            "status": "EuRepoC ingestion complete",
            "source": filepath or "app/data/eurepoc_global_dataset_1_3.csv",
            **result,
        }
    )