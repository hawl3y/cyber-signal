"""
Targeted fix script — applies pipeline logic changes without a full reprocess.

1. Re-extracts articles where the title signals a data breach but the stored
   attack_type is Malware or Phishing (the title_signals_breach guard was missing).
2. Refreshes all events so updated country/region/actor rules in refresh_event
   take effect (clears stale geography, propagates extraction actor to events
   with no named org victim).
3. Clears and re-runs attribution on all incident events.
"""
from app import create_app
from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent
from app.services.extraction import run_rule_extraction, save_extraction, mark_ready_for_clustering
from app.services.clustering import refresh_event
from app.services.actor_recognition import attribute_events

BREACH_TITLE_KEYWORDS = [
    "data breach",
    "security breach",
    "source code breach",
    "breach of",
    "breach at",
    "breach disrupts",
    "breach exposes",
]

app = create_app()
with app.app_context():
    # --- Step 1: re-extract articles with misclassified attack type ---
    print("finding articles with title-breach / body-malware-or-phishing mismatch...")
    candidates = (
        ArticleExtraction.query
        .filter(ArticleExtraction.attack_type.in_(["Malware", "Phishing"]))
        .all()
    )

    reextracted = 0
    for extraction in candidates:
        article = RawArticle.query.get(extraction.raw_article_id)
        if not article or not article.title:
            continue
        title_lower = article.title.lower()
        if any(kw in title_lower for kw in BREACH_TITLE_KEYWORDS):
            signals = run_rule_extraction(article)
            save_extraction(article.id, signals)
            mark_ready_for_clustering(article)
            reextracted += 1
            print(f"  re-extracted [{signals.get('attack_type')}]: {article.title[:80]}")

    db.session.commit()
    print(f"  re-extracted {reextracted} articles")

    # --- Step 2: refresh all events (propagates new region/actor rules) ---
    print("refreshing all events...")
    events = CyberEvent.query.all()
    for event in events:
        refresh_event(event.id)
    db.session.commit()
    print(f"  refreshed {len(events)} events")

    # --- Step 3: clear and re-run attribution ---
    print("clearing actor fields for re-attribution...")
    updated = (
        CyberEvent.query
        .filter(CyberEvent.event_signal_type == "incident")
        .update({
            "actor_name": None,
            "actor_type": None,
            "attribution_status": None,
        })
    )
    db.session.commit()
    print(f"  cleared {updated} events")

    print("re-running attribution...")
    result = attribute_events()
    print(f"  attribution: {result}")

    print("done.")
