from app import create_app
from app.jobs.extract_signals_job import extract_signals_job
from app.jobs.cluster_events_job import cluster_events_job

app = create_app()
with app.app_context():
    print("re-extracting all articles...")
    result = extract_signals_job(force=True)
    print(f"  extract: {result}")

    print("re-clustering all extractions...")
    result = cluster_events_job(force=True)
    print(f"  cluster: {result}")

    print("done.")
