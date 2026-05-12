"""
Inspect the ArticleExtraction and CyberEvent records for the Anti-DDoS DDoS incident.
Run: PYTHONPATH=. python scripts/diagnose_ddos.py
"""
from app import create_app
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink

app = create_app()
with app.app_context():
    articles = RawArticle.query.filter(
        RawArticle.title.ilike("%anti-ddos%")
        | RawArticle.title.ilike("%ddos%")
        | RawArticle.summary.ilike("%anti-ddos%")
    ).all()

    print(f"=== MATCHING ARTICLES ({len(articles)}) ===\n")
    for art in articles:
        print(f"  id={art.id} status={art.processing_status} source={art.source_name}")
        print(f"  title={art.title}")
        print(f"  summary={art.summary[:120] if art.summary else '(none)'}")

        ext = ArticleExtraction.query.filter_by(raw_article_id=art.id).first()
        if ext:
            print(f"  extraction: victim={ext.victim_org_name!r} attack={ext.attack_type!r} industry={ext.industry!r}")
        else:
            print("  extraction: (none)")
        print()

    print("=== EVENTS WITH victim=Anti-DDoS Firm (org_name OR display_label) ===\n")
    events = CyberEvent.query.filter(
        CyberEvent.victim_org_name.ilike("%anti-ddos%")
        | CyberEvent.victim_display_label.ilike("%anti-ddos%")
    ).all()
    for ev in events:
        print(f"  event id={ev.id} score={ev.confidence_score} victim={ev.victim_org_name!r}")
        print(f"  attack={ev.attack_type!r} industry={ev.industry!r}")
        links = EventSourceLink.query.filter_by(cyber_event_id=ev.id).all()
        for lnk in links:
            a = RawArticle.query.get(lnk.raw_article_id)
            if a:
                print(f"    src={a.source_name} id={a.id} title={a.title[:70]}")
        print()
