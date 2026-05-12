"""
Inspect anomalous production events:
  1. No-victim Ransomware (score=25)
  2. ABB duplicate events
Run: PYTHONPATH=. python scripts/diagnose_anomalies.py
"""
from app import create_app
from app.models import CyberEvent, EventSourceLink, RawArticle

app = create_app()
with app.app_context():
    print("=== NO-VICTIM RANSOMWARE EVENTS ===")
    events = CyberEvent.query.filter(
        CyberEvent.victim_org_name.is_(None),
        CyberEvent.attack_type == "Ransomware",
    ).all()
    if not events:
        print("  (none)\n")
    for ev in events:
        print(f"\n  event id={ev.id} score={ev.confidence_score} industry={ev.industry}")
        for lnk in EventSourceLink.query.filter_by(cyber_event_id=ev.id).all():
            a = RawArticle.query.get(lnk.raw_article_id)
            if a:
                print(f"    [{a.source_name}] {a.title}")
                print(f"    summary: {(a.summary or '')[:300]}")

    print("\n=== ABB EVENTS ===")
    abb_events = CyberEvent.query.filter(
        CyberEvent.victim_org_name.like("ABB%")
    ).order_by(CyberEvent.confidence_score.desc()).all()
    print(f"  count: {len(abb_events)}")
    for ev in abb_events:
        print(f"  id={ev.id} score={ev.confidence_score} attack={ev.attack_type} cve={ev.primary_cve_id}")
        for lnk in EventSourceLink.query.filter_by(cyber_event_id=ev.id).all():
            a = RawArticle.query.get(lnk.raw_article_id)
            if a:
                print(f"    [{a.source_name}] {a.title[:80]}")
