"""
One-shot backfill: re-apply the credibility-based event_status rule and
recompute confidence_score for every existing CyberEvent.

Run once after deploying the new trust framework so existing events pick up
the new rule. Subsequent cron runs handle new events naturally — clustering
calls refresh_event() whenever an article is added, which applies the rule.

Run with: PYTHONPATH=. python scripts/recompute_event_trust.py
"""
from collections import Counter

from app import create_app
from app.models import CyberEvent
from app.services.clustering import refresh_event


app = create_app()

with app.app_context():
    events = CyberEvent.query.all()
    total = len(events)

    before_status = Counter(e.event_status for e in events)
    before_level = Counter(e.confidence_level for e in events)

    refreshed = 0
    for event in events:
        if refresh_event(event.id):
            refreshed += 1

    events = CyberEvent.query.all()
    after_status = Counter(e.event_status for e in events)
    after_level = Counter(e.confidence_level for e in events)
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

    print(f"refreshed {refreshed}/{total} events")
    print()
    print("event_status:")
    print(f"  before: {dict(before_status)}")
    print(f"  after:  {dict(after_status)}")
    print()
    print("confidence_level:")
    print(f"  before: {dict(before_level)}")
    print(f"  after:  {dict(after_level)}")
    print()
    print("confidence_score band:")
    print(f"  after:  {dict(score_band)}")
