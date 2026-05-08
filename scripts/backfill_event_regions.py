"""
One-shot backfill: re-derive region for every CyberEvent from its country
using the canonical country->region map. Repairs cases where AI enrichment
returned a non-canonical region value (e.g. 'Georgia' for a US-based filer
in Atlanta, GA).

Idempotent: events with no country, or with country->region already correct,
pass through unchanged.

Run with: PYTHONPATH=. python scripts/backfill_event_regions.py
"""
from collections import Counter

from app import create_app
from app.extensions import db
from app.models import CyberEvent
from app.services.extraction import region_for_country


app = create_app()

with app.app_context():
    events = CyberEvent.query.all()

    before_regions = Counter(e.region for e in events)
    fixed = 0
    cleared = 0

    for event in events:
        if not event.country:
            continue
        canonical = region_for_country(event.country)
        if canonical and event.region != canonical:
            event.region = canonical
            fixed += 1
        elif canonical is None and event.region:
            # Country isn't in our taxonomy — keep region untouched.
            pass

    # Also clear obviously bogus regions on events with no country
    for event in events:
        if not event.country and event.region:
            canonical_set = set(filter(None, (region_for_country(c) for c in [
                "United States", "Canada", "Mexico", "United Kingdom", "Germany",
                "France", "Italy", "Spain", "Brazil", "China", "Japan", "India",
                "Australia",
            ]))) | {"Global"}
            if event.region not in canonical_set:
                event.region = None
                cleared += 1

    db.session.commit()

    after_regions = Counter(e.region for e in events)
    print(f"Re-derived region from country: {fixed} events updated")
    print(f"Cleared invalid orphan regions:  {cleared} events")
    print()
    print(f"Region counts before: {dict(before_regions)}")
    print(f"Region counts after:  {dict(after_regions)}")
