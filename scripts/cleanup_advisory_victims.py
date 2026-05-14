"""
Clear victim fields on events where the victim_org_name is clearly not an
organization — advisory document structures ("Executive Summary: ...",
"Defending against ...") that survived a previous pipeline run before the
NCSC source-gating fix was deployed.

Also clears actors on those events since an actor without a valid victim
violates the data integrity rules.
"""
import sys
sys.path.insert(0, ".")

from app import create_app
from app.extensions import db
from app.models import CyberEvent
from app.services.actor_recognition import attribute_events

# Patterns that are document structure, not org names (case-insensitive prefix match)
NON_ORG_VICTIM_PREFIXES = [
    "executive summary",
    "defending against",
    "protecting against",
    "advisory:",
    "alert:",
    "warning:",
]

app = create_app()
with app.app_context():
    cleared = 0
    events = CyberEvent.query.all()
    print(f"Checking {len(events)} events...")
    for event in events:
        if not event.victim_org_name:
            continue
        v = event.victim_org_name
        print(f"  id={event.id} victim={repr(v)}")
        if any(v.lower().startswith(p) for p in NON_ORG_VICTIM_PREFIXES):
            print(f"Clearing id={event.id} victim={repr(v)} actor={repr(event.actor_name)}")
            event.victim_org_name = None
            event.victim_org_normalized = None
            event.victim_display_label = None
            event.actor_name = None
            event.actor_type = None
            event.attribution_status = None
            cleared += 1

    db.session.commit()
    print(f"\nCleared {cleared} events.")

    if cleared:
        print("Re-running attribution for cleared events...")
        result = attribute_events()
        print(f"  attribution: {result}")

    print("Done.")
