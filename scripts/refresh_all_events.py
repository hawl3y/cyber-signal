"""
Re-derive all event data from current extraction logic.

Step 1: Force re-extract all articles so ArticleExtraction records reflect
        the current extraction rules (clears stale CVE display labels, full
        product titles stored as victim names, etc.).

Step 2: Re-run refresh_event on every CyberEvent so that fixes to clustering
        logic propagate to events that have no new sources and would otherwise
        never be touched by the normal pipeline.

Run this after any change to extraction or refresh_event logic to backfill
existing records.
"""
from app import create_app
from app.jobs.extract_signals_job import extract_signals_job
from app.models import CyberEvent
from app.services.clustering import refresh_event

app = create_app()

with app.app_context():
    print("Step 1: force re-extracting all articles...")
    extract_signals_job(force=True)
    print("  done.")

    print("Step 2: refreshing all events...")
    events = CyberEvent.query.order_by(CyberEvent.id).all()
    total = len(events)
    changed = 0
    for event in events:
        if refresh_event(event.id):
            changed += 1
    print(f"  refreshed {changed}/{total} events.")
