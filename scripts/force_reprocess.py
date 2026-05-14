"""
Re-extract and re-cluster all existing articles from scratch.

Use after any change to extraction.py, processing.py, or clustering.py.

Flags:
  --clear-actors   Also clear and re-run actor attribution from scratch.
                   Only use this after changes to actor_recognition.py or
                   threat_actors.py, and only after verifying that
                   diagnose_actors.py confirms attribution can restore every
                   actor that will be wiped.
"""
import sys

from app import create_app
from app.extensions import db
from app.models import CyberEvent
from app.jobs.process_articles_job import process_articles_job
from app.jobs.extract_signals_job import extract_signals_job
from app.jobs.cluster_events_job import cluster_events_job
from app.services.actor_recognition import attribute_events

clear_actors = "--clear-actors" in sys.argv

app = create_app()
with app.app_context():
    print("re-evaluating relevance for all articles...")
    result = process_articles_job(force=True)
    print(f"  process: {result}")

    print("re-extracting all articles...")
    result = extract_signals_job(force=True)
    print(f"  extract: {result}")

    print("re-clustering all extractions...")
    result = cluster_events_job(force=True)
    print(f"  cluster: {result}")

    if clear_actors:
        print("clearing actor fields for re-attribution...")
        updated = (
            CyberEvent.query
            .filter(CyberEvent.event_signal_type == "incident")
            .update({
                "actor_name": None,
                "actor_type": None,
                "attribution_status": None,
            })
        )
        db.session.commit()
        print(f"  cleared {updated} events")
    else:
        print("skipping actor clear (use --clear-actors to reset attribution)")

    print("re-running actor attribution...")
    result = attribute_events()
    print(f"  attribution: {result}")
    print(f"  is_high_impact recomputed for {result.get('high_impact_recomputed', 0)} events")

    print("done.")
