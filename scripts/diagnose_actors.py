"""
Diagnose events with missing actors — shows what the extraction found vs.
what attribution found vs. what the event currently has.
"""
from app import create_app
from app.models import CyberEvent, EventSourceLink, ArticleExtraction, RawArticle
from app.services.actor_recognition import find_actor_in_text, _event_articles_text

app = create_app()
with app.app_context():
    # Incident events with a named victim but no actor
    events = (
        CyberEvent.query
        .filter(
            CyberEvent.event_signal_type == "incident",
            CyberEvent.victim_org_name.isnot(None),
            CyberEvent.actor_name.is_(None),
        )
        .order_by(CyberEvent.confidence_score.desc())
        .limit(20)
        .all()
    )

    print(f"=== {len(events)} INCIDENT EVENTS WITH VICTIM BUT NO ACTOR ===\n")

    for event in events:
        print(f"id={event.id} victim={event.victim_org_name!r} score={event.confidence_score}")
        print(f"  title: {event.canonical_title[:80]!r}")

        # What do the extractions have?
        links = EventSourceLink.query.filter_by(cyber_event_id=event.id).all()
        for link in links:
            extraction = ArticleExtraction.query.filter_by(
                raw_article_id=link.raw_article_id
            ).first()
            if extraction:
                print(f"  extraction actor: {extraction.actor_name!r}")

        # What does find_actor_in_text find?
        combined = _event_articles_text(event)
        result = find_actor_in_text(combined)
        if result:
            print(f"  find_actor_in_text: {result[0]!r} status={result[2]!r}")
        else:
            # Show a snippet of text near any known actor names for debugging
            for keyword in ["claimed", "claiming", "attributed", "linked to", "behind"]:
                idx = combined.lower().find(keyword)
                if idx != -1:
                    snippet = combined[max(0, idx-50):idx+150]
                    print(f"  [{keyword}] ...{snippet!r}...")
                    break
            print(f"  find_actor_in_text: None")
        print()
