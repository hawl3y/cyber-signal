"""
One-shot: clear CVE IDs stored as victim_display_label or victim_org_name on CyberEvents.
CVE IDs are clustering anchors, not display entities.

Run with: PYTHONPATH=. python scripts/clear_cve_display_labels.py
"""
import re
from app import create_app
from app.extensions import db
from app.models import CyberEvent

cve_pattern = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)

app = create_app()
with app.app_context():
    events = CyberEvent.query.all()
    cleared = 0
    for e in events:
        if e.victim_display_label and cve_pattern.match(e.victim_display_label.strip()):
            print(f"  Clearing victim_display_label={e.victim_display_label!r} on: {e.canonical_title}")
            e.victim_display_label = None
            cleared += 1
        if e.victim_org_name and cve_pattern.match(e.victim_org_name.strip()):
            print(f"  Clearing victim_org_name={e.victim_org_name!r} on: {e.canonical_title}")
            e.victim_org_name = None
            e.victim_org_normalized = None
            cleared += 1
    db.session.commit()
    print(f"Done — cleared {cleared} field(s)")
