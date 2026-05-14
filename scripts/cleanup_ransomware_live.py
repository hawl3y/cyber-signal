"""
One-time cleanup: delete all ransomware.live articles and their downstream data.

With ransomware-live disabled and the bypass removed from is_relevant_incident(),
these articles are now irrelevant. The cluster zombie detection was not firing
because _ranked_extractions() didn't skip irrelevant articles — that bug is now
fixed in clustering.py. This script handles the already-persisted events.
"""

from app import create_app
from app.extensions import db
from app.models import RawArticle, ArticleExtraction, EventSourceLink, CyberEvent
from app.services.clustering import refresh_event

app = create_app()
with app.app_context():
    articles = RawArticle.query.filter_by(source_name="ransomware-live").all()
    print(f"found {len(articles)} ransomware.live articles")

    affected_event_ids = set()
    for article in articles:
        links = EventSourceLink.query.filter_by(raw_article_id=article.id).all()
        for link in links:
            affected_event_ids.add(link.cyber_event_id)

    print(f"affects {len(affected_event_ids)} events")

    # Mark all articles irrelevant so refresh_event sees them correctly
    for article in articles:
        article.processing_status = "irrelevant"
    db.session.flush()

    # refresh_event will now see ranked=[] for events whose only sources are
    # ransomware-live, and will delete them as zombies
    deleted_events = 0
    for event_id in affected_event_ids:
        result = refresh_event(event_id)
        event = CyberEvent.query.get(event_id)
        if event is None:
            deleted_events += 1

    db.session.commit()
    print(f"deleted {deleted_events} events")
    print(f"retained {len(affected_event_ids) - deleted_events} events (had other sources)")
    print("done.")
