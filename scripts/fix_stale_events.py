"""
Targeted fix script — restores actors lost by previous clear steps and
applies current pipeline logic without a full reprocess.

1. Refreshes all events (propagates any extraction-level fixes).
2. Runs attribution WITHOUT clearing first — restores actors for events
   that lost them when actor fields were previously cleared.
"""
from app import create_app
from app.extensions import db
from app.models import CyberEvent
from app.services.clustering import refresh_event
from app.services.actor_recognition import attribute_events

app = create_app()
with app.app_context():
    print("refreshing all events...")
    events = CyberEvent.query.all()
    for event in events:
        refresh_event(event.id)
    db.session.commit()
    print(f"  refreshed {len(events)} events")

    print("running attribution...")
    result = attribute_events()
    print(f"  attribution: {result}")

    print("done.")
