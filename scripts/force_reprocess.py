from app import create_app
from app.extensions import db
from app.models import CyberEvent
from app.jobs.process_articles_job import process_articles_job
from app.jobs.extract_signals_job import extract_signals_job
from app.jobs.cluster_events_job import cluster_events_job
from app.services.actor_recognition import attribute_events

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

    # Clear all actor fields on incident events so attribution runs from scratch.
    # Required after changes to actor_recognition.py or threat_actors.py so
    # previously mis-attributed events get corrected.
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

    print("re-running actor attribution...")
    result = attribute_events()
    print(f"  attribution: {result}")
    print(f"  is_high_impact recomputed for {result.get('high_impact_recomputed', 0)} events")

    print("done.")
