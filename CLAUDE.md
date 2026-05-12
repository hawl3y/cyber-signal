# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Priority Tasks

### 1. Investigate Anti-DDoS Firm victim still showing (score=80)
Extraction fix (88e2a34) and clustering refresh fix (3d22302) are deployed and force_reprocess was run, but `victim=Anti-DDoS Firm` still shows. Next step: inspect the ArticleExtraction record directly to confirm whether extraction now gives victim=None or still "Anti-DDoS Firm". If extraction is still wrong, trace through `run_rule_extraction` for that specific article.

Diagnostic to run on Render:
```
PYTHONPATH=. python scripts/diagnose_prod.py
```
Then query ArticleExtraction for the DDoS/Anti-DDoS article to see its current victim value.

### 2. Content enrichment gap — 107/138 articles irrelevant
BleepingComputer and The Record are blocked by Cloudflare in production — articles arrive with thin RSS summaries only. Without full body text, `is_relevant_incident()` rejects them (no impact keywords). This is the single biggest quality gap. Options:
- Try alternative HTTP headers / user-agent strings in the enrich job
- Accept the gap and focus on sources that do enrich (Krebs, CISA, SEC EDGAR)
- Admit core-tier articles based on title signals alone when body enrichment fails

### 3. Score=25 no-victim incidents (4 events)
Four events at score=25, victim="-". Inspect the articles manually before deciding whether to filter them earlier (processing stage) or accept them as low-signal noise.

### 4. Victimless infrastructure events
Hosting platform vulns, control panel exploits, shared-infra attacks — pipeline fails industry classification when there's no victim org. Design a deterministic classifier for this pattern at the extraction or processing stage. No one-off fixes.

---

## Product Purpose

Cyber Signal answers "What matters right now?" in under 10 seconds. It turns fragmented cyber reporting into structured, scannable events for rapid situational awareness. **The unit of value is the event, not the article.**

**What it is**: a structured cyber incident intelligence layer — a fully deterministic pipeline with rule-based enrichment, and a real-time decision surface for cyber activity.

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
- **Web service**: serves API + UI, fast, read-only on enriched data
- **Cron job**: runs pipeline every 4h, mutates enriched data

**Critical**: only the cron job is permitted to mutate enriched data. Web requests must never write enrichment fields.

Note: `AI_ENRICHMENT_ENABLED` is a vestigial env var — AI enrichment has been fully removed. All attribution and classification is deterministic.

### Working Method

1. Inspect output first
2. Identify a real defect (not a hypothetical one)
3. Map it to a pipeline stage
4. Change one thing
5. Test locally, verify in production
6. Commit

Avoid: guessing, over-engineering, one-off fixes.

---

## Overview

**Cyber Signal** is a single-page cyber event intelligence application that ingests cyber security news and alerts, extracts structured signals, clusters related activity into unified events, and presents a filterable feed. The MVP focuses on live incident data with no historical dataset.

## Tech Stack

- **Backend**: Flask with Flask-SQLAlchemy, Flask-Migrate
- **Database**: PostgreSQL
- **Scheduling**: External cron job (Render cron service) — no in-process scheduler
- **Server**: Gunicorn
- **Frontend**: Vanilla JavaScript (client-side filtering, localStorage)
- **Data Processing**: feedparser, requests for ingestion
- **AI Enrichment**: Removed. Actor attribution is now fully deterministic via `actor_recognition.py`.

## Architecture

### High-Level Data Flow

The application implements a live pipeline with six sequential stages:

```
Ingest → Process → Extract → Cluster → Attribute → Audit
```

1. **Ingest**: Fetches from RSS feeds and JSON/EDGAR APIs
2. **Process**: Filters for concrete incidents vs. advisory noise
3. **Extract**: Structures incident signals (victim org, attack type, CVE, geography)
4. **Cluster**: Groups related extractions into unified CyberEvent objects; computes confidence score
5. **Attribute**: Deterministic threat-actor matching against curated knowledge base (`app/data/threat_actors.py`)
6. **Audit**: Scans recent articles for unrecognized actor candidates; persists to `ActorCandidateSighting` for curator review

### Core Models

- **RawArticle**: Raw ingested content with metadata (source, title, summary, content)
- **ArticleExtraction**: Structured signals extracted from a single article (victim, attack_type, actor, confidence)
- **CyberEvent**: Unified event representing one incident, aggregated from multiple extractions
- **EventSourceLink**: Junction table linking CyberEvent to source RawArticles with match scores and primary-source flag
- **AutomationRun**: Tracks scheduler execution history
- **ActorCandidateSighting**: Unrecognized actor candidates flagged by the audit stage for curator review
- **EnrichmentAuditLog**: Per-event enrichment call audit (inputs, outputs, tokens, duration)
- **SourceReputation**: Source credibility scoring (not active in MVP)

### Service Layers

- **ingestion.py**: Feeds & fetching; handles RSS, JSON, and SEC EDGAR sources
- **processing.py**: Filters articles for relevance (incident vs. noise)
- **extraction.py**: Pattern-based signal extraction using regex and heuristics
- **clustering.py**: Matches extractions to existing events or creates new ones; computes deterministic `confidence_score`
- **actor_recognition.py**: Deterministic threat-actor attribution via curated `THREAT_ACTORS` knowledge base
- **actor_candidate_audit.py**: Shared logic for finding unrecognized actor candidates near attribution language
- **summary.py**: Filters and formats events for API responses
- **taxonomy.py**: Normalization maps for threat types, entity anchors, industries, actors

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
- Filter controls: Time Range, Signal Type, Industry, Threat Type (formerly "Attack Type")
- Event list sorted by priority tuple (see Event Prioritization below)
- Event cards: expandable detail panel on click; primary-source badge nested in publisher cell
- LocalStorage persists filter state

### Database Schema

Key fields on CyberEvent:
- Victim: `victim_org_name`, `victim_org_normalized`, `victim_display_label`, `victim_entity_type`, `industry`, `region`, `country`, `city`, `latitude`, `longitude`
- Attack: `attack_type`, `access_vector`, `impact_type`, `vuln_status`, `primary_cve_id`, `zero_day_flag`, `is_high_impact`
- Actor: `actor_name`, `actor_type`, `attribution_status`
- Signal: `event_signal_type` (incident|activity), `event_status` (emerging|confirmed), `confidence_level`, `confidence_score` (0–100 float)
- Tracking: `first_seen_at`, `last_seen_at`, `event_occurred_at`, `created_at`, `updated_at`, `last_confidence_scored_at`
- Aggregation: `source_count`, `high_credibility_source_count`, `event_cluster_key`
- Content: `summary_short`, `summary_medium`, `tags`

---

## Development

### Environment Setup

The `.venv` virtualenv is always pre-activated before Claude Code is launched. 
Never prefix commands with `source .venv/bin/activate &&` — it is redundant and 
triggers unnecessary permission prompts. Use `python3` directly.

Requires `.env` with:
```
SECRET_KEY=<random-string>
DATABASE_URL=postgresql://<user>:<password>@<host>:5432/<dbname>
AI_ENRICHMENT_ENABLED=true|false (optional, vestigial — actor attribution is now deterministic)
SEC_USER_AGENT="Cyber Signal contact@yourdomain" (required for SEC EDGAR ingestion, per their fair-use policy)
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

---

## Key Design Patterns & Conventions

### Threat Type Taxonomy

The `attack_type` field is labeled "Threat Type" in the UI. It covers both attack methods (incidents) and vulnerability classes (activity events). The full vocabulary, defined in `app/services/taxonomy.py`:

| Type | Typical source |
|---|---|
| Ransomware | Incident news |
| Data Breach | Incident news |
| Phishing | Incident news |
| DDoS | Incident news |
| Malware | Incident news |
| Account Compromise | Incident news |
| Supply Chain | Incident or advisory |
| Exploitation | Active in-the-wild exploitation (CVE present, no more specific class) |
| Authentication Bypass | CISA/vendor advisories |
| Remote Code Execution | CISA/vendor advisories |
| Privilege Escalation | CISA/vendor advisories |
| Injection | CISA/vendor advisories (SQL, command, etc.) |
| Disruption | Incident news |
| Unknown | No signal found |

Detection order matters: specific vulnerability classes (Authentication Bypass, RCE, etc.) are checked **before** the generic `Exploitation` catch-all so advisory-style events get a precise label. Do not move `_has_exploitation_signal` above the specific checks.

### Extraction Heuristics

**processing.py** filters out noise via keyword patterns:
- Advisory noise in CISA feeds (e.g., "defending against", "best practices")
- Legal aftermath articles (e.g., "sentenced to", plea deals)

**extraction.py** uses regex-based patterns to detect:
- Named victim organizations (vs. generic "company")
- Threat type classification (see Threat Type Taxonomy above)
- Geography and CVE references
- Actor confidence (claimed vs. suspected)

### Clustering Logic

**clustering.py** matches ArticleExtraction records to CyberEvent by:
1. Exact victim org + attack type (highest priority)
2. Victim org + country + attack type
3. Organization acronym + attack type
4. Shared geography + attack type (lower confidence)

Primary source detection identifies direct victim statements (keywords like "the company said", "in a filing").

After clustering, `_compute_confidence_score()` derives a deterministic 0–100 float from source count, source class (primary disclosure, trusted-alone, official), and actor presence.

### Threat-Actor Attribution

**actor_recognition.py** runs after clustering. For each incident event with a victim and no (or generic) actor, it scans the combined text of all linked articles for any name or alias in the curated `THREAT_ACTORS` knowledge base (`app/data/threat_actors.py`). Attribution status is inferred from surrounding context patterns (claimed, suspected, etc.).

Rules:
- `signal_type=activity` events are never attributed
- `victim_org_name` must be set (no victim → no actor)
- Already-attributed events are skipped unless the existing name is generic

### Actor Candidate Audit

**actor_candidate_audit.py** (shared logic) + **actor_candidate_audit_job.py** (pipeline stage):
- Runs after attribution; scans the last 14 days of articles for capitalized phrases near attribution language that did not match any known actor
- Persists unique sightings to `ActorCandidateSighting` for curator review
- `scripts/audit_unrecognized_actors.py` renders a human-friendly report from the persisted sightings

### Source Registry

**sources.py** defines active ingestion sources:
- **The Record** (incident news via RSS, tier: core)
- **BleepingComputer** (incident news via RSS, tier: core)
- **Krebs on Security** (curated incident news, tier: curated, `tier_trusted_alone`)
- **CISA Advisories** (official alerts via RSS, tier: curated)
- **CISA KEV** (exploited vulnerability index via JSON, tier: curated)
- **SEC EDGAR** (material cybersecurity 8-K filings via EDGAR full-text search, tier: official, `tier_trusted_alone`)

`tier_trusted_alone=True` means a single article from that source is enough to confirm an event (affects confidence scoring).

### Event Prioritization

Frontend sorts events by tuple (do not reorder without product review):
1. Signal type (incidents before activity)
2. Confidence score descending (higher trust first)
3. High-impact flag (high-impact first within trust band)
4. Source count descending
5. Recency (most recent first)

---

## Common Tasks

### Add a New Ingestion Source

1. Edit `app/utils/sources.py`: add dict to `SOURCE_REGISTRY` with name, ingest_type, url, tier
2. If JSON: implement handler in `services/ingestion.py:fetch_source_items()`
3. If RSS: feedparser handles it automatically
4. Test via `POST /api/ingest/` endpoint or pipeline run

### Modify Extraction Heuristics or Threat Type Classification

Edit `app/services/extraction.py` or `app/services/processing.py`:
- Add regex patterns to `_combined_article_text()` matching
- Adjust confidence scoring in `ArticleExtraction` creation
- To add a new threat type: add it to `ATTACK_TYPES` and `LEGACY_ATTACK_TYPE_MAP` in `taxonomy.py`, then add detection keywords in `extraction.py` before the `_has_exploitation_signal` catch-all
- After changing classification logic, force-reprocess existing records (see Force Reprocessing below)

### Adjust Event Clustering

Edit `app/services/clustering.py`:
- Change matching weights or thresholds in `_match_extraction_to_event()`
- Add/remove clustering strategies (victim+attack, geography, actor, etc.)
- Modify `event_cluster_key` generation or `_compute_confidence_score()`

### Add a Threat Actor

Edit `app/data/threat_actors.py`:
- Append a new entry with `aliases` and `actor_type`
- Use the most commonly used canonical name; put alternate names in aliases
- Aliases are matched case-insensitively with word boundaries

### Query Events Programmatically

```python
from app.services.summary import get_filtered_events

events = get_filtered_events(
    industry="Healthcare",
    region="North America",
    attack_type="Ransomware",
    time_range="30d"
)
```

---

## Deployment Notes

- **Scheduling**: Render cron service runs `python scripts/run_pipeline_once.py` on a fixed schedule — the web service process never runs the pipeline
- **Database**: PostgreSQL backing store; migrations must be run before app start
- **Single-Instance**: MVP designed for single-instance deployment; clustering logic assumes no race conditions
- **Environment**: All secrets and URLs via `.env`; no hardcoded credentials

---

## Operations Runbook

All commands require `PYTHONPATH=.` and must be run from the repo root. The `.venv` is pre-activated — never prefix with `source .venv/bin/activate`. These same commands work identically locally and on the Render production shell.

### Rule: after changing extraction or processing logic

The pipeline only processes `pending` articles. Any change to `extraction.py`, `processing.py`, or `clustering.py` **must** be followed by a force reprocess to apply the new logic to existing articles.

```bash
PYTHONPATH=. python scripts/force_reprocess.py
```

This re-extracts all articles and re-clusters everything. Run it after every deploy that touches pipeline logic.

---

### Canonical scripts (always use these — never one-off heredocs)

**Run the full pipeline once** (ingest → enrich → process → extract → cluster → attribute → audit):
```bash
PYTHONPATH=. python scripts/run_pipeline_once.py
```

**Force re-extract and re-cluster all existing articles** (use after any extraction/processing logic change):
```bash
PYTHONPATH=. python scripts/force_reprocess.py
```

**Inspect current production state** (events with scores/sources/victims/attack types, article status counts, recent extractions):
```bash
PYTHONPATH=. python scripts/diagnose_prod.py
```

**View actor candidate audit report**:
```bash
PYTHONPATH=. python scripts/audit_unrecognized_actors.py
```

---

### Diagnosis workflow

When output looks wrong (bad attack type, missing victim, wrong industry, events not clustering):

1. Run `diagnose_prod.py` to see the current event/article state at a glance.
2. If a specific article/victim needs closer inspection, write a targeted script in `scripts/` (e.g. `diagnose_canvas.py`) — never use inline heredocs in the Render shell, they fail.
3. Fix the pipeline stage (not the symptom).
4. Push, wait for deploy, then run `force_reprocess.py`.
5. Re-run `diagnose_prod.py` to verify.

---

### Reset all content (fresh start)

```bash
PYTHONPATH=. python scripts/reset_content.py
```

If that script doesn't exist, create it first — never run destructive SQL inline.
