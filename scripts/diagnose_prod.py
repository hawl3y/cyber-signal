from collections import Counter

from app import create_app
from app.models import ArticleExtraction, CyberEvent, EventSourceLink, RawArticle

app = create_app()
with app.app_context():
    events = CyberEvent.query.order_by(CyberEvent.confidence_score.desc()).all()
    print("=== EVENTS (" + str(len(events)) + ") ===")
    for e in events:
        victim = (e.victim_org_name or e.victim_display_label or "-")[:20]
        actor = " [" + e.actor_name + "]" if e.actor_name else ""
        links = EventSourceLink.query.filter_by(cyber_event_id=e.id).count()
        score = str(int(e.confidence_score or 0))
        line = (
            "  score=" + score
            + " src=" + str(links)
            + " [" + str(e.event_signal_type) + "]"
            + " victim=" + victim
            + " attack=" + str(e.attack_type)
            + " industry=" + str(e.industry)
            + actor
        )
        print(line)

    print()
    articles = RawArticle.query.all()
    status_counts = Counter(a.processing_status for a in articles)
    print("=== ARTICLES (" + str(len(articles)) + ") ===")
    for status, count in sorted(status_counts.items()):
        print("  " + str(status) + ": " + str(count))

    print()
    print("=== RECENT EXTRACTIONS (last 15) ===")
    exts = ArticleExtraction.query.order_by(ArticleExtraction.id.desc()).limit(15).all()
    for ext in exts:
        art = RawArticle.query.filter_by(id=ext.raw_article_id).first()
        title = (art.title or "")[:50] if art else "N/A"
        print(
            "  victim=" + str(ext.victim_org_name or "-")[:20]
            + " attack=" + str(ext.attack_type)
            + " | " + title
        )
