from app import create_app
from app.models import ArticleExtraction, CyberEvent, EventSourceLink, RawArticle

app = create_app()
with app.app_context():
    articles = RawArticle.query.filter(
        RawArticle.title.ilike("%canvas%") | RawArticle.title.ilike("%instructure%")
    ).all()

    print("=== CANVAS/INSTRUCTURE ARTICLES ===")
    for a in articles:
        print(f"\n  id={a.id} status={a.processing_status} enriched={a.content_enriched}")
        print(f"  source={a.source_name}")
        print(f"  title={a.title}")
        summary_snippet = (a.summary or "")[:200]
        print(f"  summary={summary_snippet}")
        content_snippet = (a.content or "")[:200]
        print(f"  content={content_snippet}")

        ext = ArticleExtraction.query.filter_by(raw_article_id=a.id).first()
        if ext:
            print(f"  extraction: victim={ext.victim_org_name} attack={ext.attack_type} industry={ext.industry}")
        else:
            print(f"  extraction: none")

    print("\n=== CANVAS/INSTRUCTURE EVENTS ===")
    events = CyberEvent.query.filter(
        CyberEvent.victim_org_name.ilike("%canvas%") |
        CyberEvent.victim_org_name.ilike("%instructure%") |
        CyberEvent.victim_display_label.ilike("%canvas%") |
        CyberEvent.victim_display_label.ilike("%instructure%")
    ).all()
    for e in events:
        links = EventSourceLink.query.filter_by(cyber_event_id=e.id).all()
        print(f"\n  id={e.id} score={e.confidence_score} victim={e.victim_org_name} display={e.victim_display_label}")
        print(f"  attack={e.attack_type} industry={e.industry} actor={e.actor_name}")
        for lnk in links:
            art = RawArticle.query.filter_by(id=lnk.raw_article_id).first()
            src = art.source_name if art else "?"
            title = (art.title or "")[:60] if art else "?"
            print(f"    src={src} title={title}")
