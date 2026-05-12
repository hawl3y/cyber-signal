"""
Inspect all CyberEvent records with no victim (victim_org_name=NULL and victim_display_label=NULL).
Shows the linked source articles so we can decide whether to filter or accept each event.
Run: PYTHONPATH=. python scripts/diagnose_no_victim.py
"""
from app import create_app
from app.models import CyberEvent, EventSourceLink, RawArticle

app = create_app()
with app.app_context():
    events = (
        CyberEvent.query
        .filter(
            CyberEvent.victim_org_name.is_(None),
            CyberEvent.victim_display_label.is_(None),
        )
        .order_by(CyberEvent.confidence_score.desc())
        .all()
    )

    print(f"=== NO-VICTIM EVENTS ({len(events)}) ===\n")
    for ev in events:
        print(
            f"  event id={ev.id} score={ev.confidence_score} "
            f"type={ev.event_signal_type} attack={ev.attack_type!r} industry={ev.industry!r}"
        )
        links = EventSourceLink.query.filter_by(cyber_event_id=ev.id).all()
        for lnk in links:
            a = RawArticle.query.get(lnk.raw_article_id)
            if a:
                print(f"    [{a.source_name}] status={a.processing_status}")
                print(f"    title: {a.title}")
                print(f"    summary: {(a.summary or '')[:200]}")
        print()
