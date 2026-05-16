# Cyber BLUF

Cyber BLUF is a single-page cyber event intelligence application that provides a clean, structured view of high-signal cyber activity.

It ingests reporting from curated sources, extracts structured signals, clusters related activity into unified events, and presents a fast, filterable view of what matters now.

## Current Scope (MVP)

- Unified event feed (incidents and activity)
- Sources:
  - Curated cyber news (incidents)
  - CISA KEV and advisories (activity)
- Live ingestion pipeline:
  - ingest > process > extract > cluster
- Simple summary and trends aligned with filters
- No historical dataset active in current MVP
- No enrichment/scoring pipeline in active use

## Tech Stack

- Flask
- PostgreSQL
- SQLAlchemy + Alembic
- APScheduler (in-process automation)
- Gunicorn

## Local Development

Activate environment:

source .venv/bin/activate

Run app (no scheduler):

RUN_SCHEDULER=false gunicorn --bind 0.0.0.0:5001 "app:create_app()"

Run app with scheduler:

RUN_SCHEDULER=true python run.py

## Reset Data

python - <<'PY'
from app import create_app
from app.extensions import db
from app.models import (
EventSourceLink,
ArticleExtraction,
CyberEvent,
RawArticle,
)

app = create_app()

with app.app_context():
EventSourceLink.query.delete()
ArticleExtraction.query.delete()
CyberEvent.query.delete()
RawArticle.query.delete()
db.session.commit()
print("Content reset complete.")
PY

## Run Pipeline

python - <<'PY'
from app import create_app
from app.jobs import run_full_pipeline

app = create_app()

with app.app_context():
result = run_full_pipeline(force_extract=False)
print(result)
PY

## Notes

- Scheduler is controlled via `RUN_SCHEDULER`
- Only one process should run with scheduler enabled
- Designed for single-instance deployment in MVP

## Deployment (Planned)

Target platform: Render

- Flask web service using Gunicorn
- PostgreSQL backing database
- Scheduler runs in-process in single instance