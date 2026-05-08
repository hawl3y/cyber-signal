# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Product Purpose

Cyber Signal answers "What matters right now?" in under 10 seconds. It turns fragmented cyber reporting into structured, scannable events for rapid situational awareness. **The unit of value is the event, not the article.**

**What it is**: a structured cyber incident intelligence layer — a deterministic pipeline with AI-assisted enrichment, and a real-time decision surface for cyber activity.

**What it is not**: a news aggregator, SIEM, threat intelligence platform, or analytics dashboard.

### Event Model

Two and only two event kinds:
- **Incident** — real-world cyber events with impact (breaches, ransomware, system compromise)
- **Activity** — high-signal risk indicators (known exploited vulns, active exploitation campaigns)

### Design Principles

- **Deterministic logic first; AI fills gaps only.** Never replace working deterministic logic with an AI call.
- **Never overwrite enriched data.** Cached enrichment is permanent unless explicitly invalidated.
- **No hallucinated fields, no generic actors.** Generic actors are discarded, not stored.
- **No hard-coded one-off fixes.** If a single article exposes a gap, fix the pipeline stage, not the symptom.
- **Quality over recall.** False positives (noise) are worse than false negatives.

### Data Integrity Rules (hard constraints)

- No victim → no actor
- No actor → no attribution
- Generic actor → discarded
- Activity events: never enrich actor

### Operational Boundary

Two deployment modes share the same code:
- **Web service** (`AI_ENRICHMENT_ENABLED=false`): serves API + UI, fast, read-only on enriched data
- **Cron job** (`AI_ENRICHMENT_ENABLED=true`): runs pipeline every 4h, mutates enriched data

**Critical**: only the cron job is permitted to mutate enriched data. Web requests must never write enrichment fields.

### Working Method

1. Inspect output first
2. Identify a real defect (not a hypothetical one)
3. Map it to a pipeline stage
4. Change one thing
5. Test locally, verify in production
6. Commit

Avoid: guessing, over-engineering, one-off fixes.

## Overview

**Cyber Signal** is a single-page cyber event intelligence application that ingests cyber security news and alerts, extracts structured signals, clusters related activity into unified events, and presents a filterable feed. The MVP focuses on live incident data with no historical dataset.

## Tech Stack

- **Backend**: Flask with Flask-SQLAlchemy, Flask-Migrate
- **Database**: PostgreSQL
- **Scheduling**: External cron job (Render cron service) — no in-process scheduler
- **Server**: Gunicorn
- **Frontend**: Vanilla JavaScript (client-side filtering, localStorage)
- **Data Processing**: feedparser, requests for ingestion
- **AI Enrichment** (optional): Grok API via xAI

## Architecture

### High-Level Data Flow

The application implements a live pipeline with four sequential stages:

```
Ingest → Process → Extract → Cluster → Event Feed
```

1. **Ingest**: Fetches from RSS feeds and JSON APIs (CISA KEV, curated news sources)
2. **Process**: Filters for concrete incidents vs. advisory noise
3. **Extract**: Structures incident signals (victim org, attack type, actor, CVE, geography)
4. **Cluster**: Groups related extractions into unified CyberEvent objects
5. **Event Feed**: Queries and sorts events for frontend consumption

### Core Models

- **RawArticle**: Raw ingested content with metadata (source, title, summary, content)
- **ArticleExtraction**: Structured signals extracted from a single article (victim, attack_type, actor, confidence)
- **CyberEvent**: Unified event representing one incident, aggregated from multiple extractions
- **EventSourceLink**: Junction table linking CyberEvent to source RawArticles with match scores
- **AutomationRun**: Tracks scheduler execution history
- **SourceReputation**: Source credibility scoring (not active in MVP)

### Service Layers

- **ingestion.py**: Feeds & fetching; handles RSS and JSON sources
- **processing.py**: Filters articles for relevance (incident vs. noise)
- **extraction.py**: Pattern-based signal extraction using regex and heuristics; optional AI enrichment
- **clustering.py**: Matches extractions to existing events or creates new ones
- **summary.py**: Filters and formats events for API responses
- **ai_enrichment.py**: Optional structured enrichment via Grok API (victim, attack, actor, attribution)
- **taxonomy.py**: Normalization maps for attack types, entity anchors, industries, actors

### API Endpoints

All endpoints live in `/api` and are stateless query/trigger routes:

- **`GET /api/events/`**: Filtered list of cyber events (supports industry, region, attack_type, time_range, limit, offset)
- **`GET /api/summary/`**: Aggregate counts and top items by category
- **`GET /api/summary/trends`**: Trend analysis aligned with filters
- **`POST /api/ingest/`**: Manually trigger ingest job
- **`POST /api/process/`**: Manually trigger processing job
- **`POST /api/extract/`**: Manually trigger extraction job (with optional `force` param)
- **`GET /api/extract/debug`**: Debug extraction results
- **`POST /api/cluster/`**: Manually trigger clustering job
- **`GET /api/automation/status`**: Scheduler state and last run details

### Frontend

Single-page app loaded at `/`:
- Filter controls (time_range, industry, region, attack_type)
- Event list sorted by: signal_type (incidents prioritized), actor presence, high-impact flag, verification, source count, recency
- LocalStorage persists filter state
- Event cards display victim, context, location, attribution, attack type

### Database Schema

Key fields on CyberEvent (inherited from ArticleExtraction extraction pipeline):
- Victim: `victim_org_name`, `victim_org_normalized`, `victim_entity_type`, `industry`, `region`, `country`, `city`
- Attack: `attack_type`, `access_vector`, `impact_type`, `vuln_status`, `primary_cve_id`, `zero_day_flag`
- Actor: `actor_name`, `actor_type`, `attribution_status`
- Signal: `event_signal_type` (incident|activity), `event_status` (emerging|confirmed), `confidence_level`
- Tracking: `first_seen_at`, `last_seen_at`, `event_occurred_at`, `created_at`, `updated_at`
- Aggregation: `source_count`, `high_credibility_source_count`, `event_cluster_key`

## Development

### Environment Setup

```bash
source .venv/bin/activate
```

Requires `.env` with:
```
SECRET_KEY=<random-string>
DATABASE_URL=postgresql://<user>:<password>@<host>:5432/<dbname>
AI_ENRICHMENT_ENABLED=true|false (optional)
XAI_API_KEY=<grok-api-key> (optional)
SEC_USER_AGENT="Cyber Signal contact@yourdomain" (optional, identifies you to SEC EDGAR per their fair-use policy)
```

### Running the App

**Web service** (API + UI, no pipeline execution):
```bash
gunicorn --bind 0.0.0.0:5001 "app:create_app()"
```

**Development with hot reload** (for frontend/route changes):
```bash
python run.py
```

**Run the pipeline once** (as the Render cron job does):
```bash
python scripts/run_pipeline_once.py
```

**Local dev with in-process scheduler** (APScheduler code still exists but is not used in production):
```bash
RUN_SCHEDULER=true AUTOMATION_ENABLED=true AUTOMATION_INTERVAL_MINUTES=60 python run.py
```

### Database Migrations

```bash
# Create a new migration after model changes
flask db migrate -m "description"

# Apply migrations
flask db upgrade

# Revert one migration
flask db downgrade

# Check current migration status
flask db current
```

### Resetting Content

Clear all data for a fresh start:
```bash
python - <<'PY'
from app import create_app
from app.extensions import db
from app.models import EventSourceLink, ArticleExtraction, CyberEvent, RawArticle

app = create_app()
with app.app_context():
    EventSourceLink.query.delete()
    ArticleExtraction.query.delete()
    CyberEvent.query.delete()
    RawArticle.query.delete()
    db.session.commit()
    print("Content reset complete.")
PY
```

## Key Design Patterns & Conventions

### Extraction Heuristics

**processing.py** filters out noise via keyword patterns:
- Advisory noise in CISA feeds (e.g., "defending against", "best practices")
- Legal aftermath articles (e.g., "sentenced to", plea deals)

**extraction.py** uses regex-based patterns to detect:
- Named victim organizations (vs. generic "company")
- Exploitation signals (code execution, auth bypass)
- Concrete attack classes
- Geography and CVE references
- Actor confidence (claimed vs. suspected)

AI enrichment is optional and uses allowlists (ALLOWED_INDUSTRIES, ALLOWED_ATTACK_TYPES, ALLOWED_ACTOR_TYPES, ALLOWED_ATTRIBUTION_STATUS) to reject invalid values.

### Clustering Logic

**clustering.py** matches ArticleExtraction records to CyberEvent by:
1. Exact victim org + attack type (highest priority)
2. Victim org + country + attack type
3. Organization acronym + attack type
4. Shared geography + attack type (lower confidence)

Primary source detection identifies direct victim statements (keywords like "the company said", "in a filing").

### Source Registry

**sources.py** defines active ingestion sources:
- **The Record** (incident news via RSS, tier: core)
- **BleepingComputer** (incident news via RSS, tier: core)
- **Krebs on Security** (curated incident news, tier: curated)
- **CISA Advisories** (official alerts via RSS, tier: curated)
- **CISA KEV** (exploited vulnerability index via JSON, tier: curated)

Each source has metadata (ingest_type, signal_kind, source_class) that affects filtering and prioritization.

### Event Prioritization

Frontend sorts events by tuple (do not reorder without product review):
1. Signal type (incidents before activity)
2. Actor presence (attributed before unattributed)
3. High-impact flag
4. Event status (confirmed before emerging)
5. Source count (descending)
6. Recency (most recent first)

## Common Tasks

### Add a New Ingestion Source

1. Edit `app/utils/sources.py`: add dict to SOURCE_REGISTRY with name, ingest_type, url, tier
2. If JSON: implement handler in `services/ingestion.py:fetch_source_items()`
3. If RSS: feedparser handles it automatically
4. Test via `POST /api/ingest/` endpoint or pipeline run

### Modify Extraction Heuristics

Edit `app/services/extraction.py` or `app/services/processing.py`:
- Add regex patterns to `_combined_article_text()` matching
- Adjust confidence scoring in `ArticleExtraction` creation
- Toggle AI enrichment via `AI_ENRICHMENT_ENABLED` env var

### Adjust Event Clustering

Edit `app/services/clustering.py`:
- Change matching weights or thresholds in `_match_extraction_to_event()`
- Add/remove clustering strategies (victim+attack, geography, actor, etc.)
- Modify `event_cluster_key` generation

### Query Events Programmatically

Use the summary service in Python:
```python
from app.services.summary import get_filtered_events

events = get_filtered_events(
    industry="Healthcare",
    region="North America",
    attack_type="Ransomware",
    time_range="30d"
)
```

## Deployment Notes

- **Scheduling**: Render cron service runs `python scripts/run_pipeline_once.py` on a fixed schedule — the web service process never runs the pipeline
- **Database**: PostgreSQL backing store; migrations must be run before app start
- **Single-Instance**: MVP designed for single-instance deployment; clustering logic assumes no race conditions
- **Environment**: All secrets and URLs via `.env`; no hardcoded credentials

## Testing & Debugging

**Check automation status**:
```bash
curl http://localhost:5001/api/automation/status
```

**Inspect raw articles**:
```bash
python - <<'PY'
from app import create_app
from app.models import RawArticle

app = create_app()
with app.app_context():
    articles = RawArticle.query.limit(5).all()
    for a in articles:
        print(f"{a.id}: {a.title[:50]} ({a.source_name})")
PY
```

**Check extraction results**:
```bash
python - <<'PY'
from app import create_app
from app.models import ArticleExtraction

app = create_app()
with app.app_context():
    extractions = ArticleExtraction.query.limit(5).all()
    for e in extractions:
        print(f"{e.id}: victim={e.victim_org_name}, attack={e.attack_type}, confidence={e.extraction_confidence}")
PY
```

**View clustered events**:
```bash
curl "http://localhost:5001/api/events?limit=10&offset=0" | jq .
```

