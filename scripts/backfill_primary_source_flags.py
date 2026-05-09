"""
One-shot backfill: re-evaluate is_primary_source for all existing EventSourceLinks
using the current _is_primary_source_article logic, then recompute event trust scores.

Run after deploying updated primary source detection patterns so existing events
pick up the corrected flag. Future clustering runs apply the flag on creation and
now also on subsequent re-runs of the same article.

Run with: PYTHONPATH=. python scripts/backfill_primary_source_flags.py
"""
from collections import Counter

from app import create_app
from app.extensions import db
from app.models import EventSourceLink, CyberEvent
from app.services.clustering import _is_primary_source_article, refresh_event


app = create_app()

with app.app_context():
    links = EventSourceLink.query.all()
    updated = 0
    for link in links:
        if not link.raw_article:
            continue
        new_flag = _is_primary_source_article(link.raw_article)
        if link.is_primary_source != new_flag:
            link.is_primary_source = new_flag
            updated += 1
    db.session.commit()
    print(f"Updated is_primary_source on {updated}/{len(links)} links")

    print("\nRecomputing event trust scores...")
    events = CyberEvent.query.all()
    before_level = Counter(e.confidence_level for e in events)
    before_status = Counter(e.event_status for e in events)

    for event in events:
        refresh_event(event.id)

    events = CyberEvent.query.all()
    after_level = Counter(e.confidence_level for e in events)
    after_status = Counter(e.event_status for e in events)
    score_band = Counter()
    for event in events:
        score = event.confidence_score
        if score is None:
            score_band["none"] += 1
        elif score >= 75:
            score_band["high (>=75)"] += 1
        elif score >= 50:
            score_band["med (50-74)"] += 1
        else:
            score_band["low (<50)"] += 1

    print(f"\nconfidence_level:")
    print(f"  before: {dict(before_level)}")
    print(f"  after:  {dict(after_level)}")
    print(f"\nevent_status:")
    print(f"  before: {dict(before_status)}")
    print(f"  after:  {dict(after_status)}")
    print(f"\nconfidence_score band:")
    print(f"  after:  {dict(score_band)}")
