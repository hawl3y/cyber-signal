"""
Show full title + summary for events likely to be noise:
- All incidents score <= 30
- Foxconn (industry=Education)
- Trellix (industry=Government)
- No-victim incidents
"""
from app import create_app
from app.models import CyberEvent, EventSourceLink, RawArticle

app = create_app()
with app.app_context():
    events = CyberEvent.query.filter(
        CyberEvent.event_signal_type == "incident"
    ).order_by(CyberEvent.confidence_score.desc()).all()

    def show(label, evts):
        print(f"\n=== {label} ({len(evts)}) ===")
        for e in evts:
            print(f"\nid={e.id} score={e.confidence_score} victim={e.victim_org_name!r} attack={e.attack_type!r} industry={e.industry!r} actor={e.actor_name!r}")
            print(f"  title: {e.canonical_title!r}")
            link = EventSourceLink.query.filter_by(cyber_event_id=e.id).first()
            if link:
                a = RawArticle.query.get(link.raw_article_id)
                if a:
                    print(f"  source: {a.source_name!r}")
                    print(f"  summary: {(a.summary or '')[:200]!r}")

    low_score = [e for e in events if e.confidence_score <= 30]
    show("LOW SCORE INCIDENTS (<=30)", low_score)

    mismatched = [e for e in events if
        (e.victim_org_name == 'Foxconn' and e.industry == 'Education') or
        (e.victim_org_name == 'Trellix' and e.industry == 'Government')
    ]
    show("INDUSTRY MISMATCHES", mismatched)
