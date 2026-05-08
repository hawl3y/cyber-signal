"""
One-shot backfill: re-extract victim_org_name on articles whose titles end
with audience descriptors ("X users", "X customers", "X citizens", etc.).

These are titles like "Acme confirms breach affecting Russian users" where
the legacy extraction captured "Russian users", lowercase-stripped it to
"Russian", and stored a demonym as the victim org. The pipeline is now
fixed for new ingests (audience-tail captures are rejected and a strong
"X confirms/discloses" subject pattern fires first). This script repairs
existing rows.

Idempotent: re-running has no effect on already-correct events.

Run with: PYTHONPATH=. python scripts/backfill_audience_tail_victims.py
"""
import re

from app import create_app
from app.extensions import db
from app.models import ArticleExtraction, CyberEvent, EventSourceLink, RawArticle
from app.services.extraction import run_rule_extraction, save_extraction


AUDIENCE_TAIL_RE = re.compile(
    r"\b(?:users?|customers?|citizens?|people|visitors?|clients?|"
    r"residents?|nationals?|workers?|members?|subscribers?|patients?|"
    r"students?|employees?|consumers?|tenants?|guests?|riders?|"
    r"shoppers?|viewers?|readers?|listeners?)\b",
    flags=re.IGNORECASE,
)


def main():
    app = create_app()
    with app.app_context():
        candidates = (
            RawArticle.query
            .filter(RawArticle.title.op("~*")(r"affecting .+ (users|customers|citizens|people|visitors|clients|residents|nationals)"))
            .all()
        )
        print(f"Articles matching 'affecting X audience' pattern: {len(candidates)}")

        fixed_extractions = 0
        fixed_events = 0
        for article in candidates:
            if not AUDIENCE_TAIL_RE.search(article.title or ""):
                continue

            extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()
            if not extraction:
                continue

            old_victim = extraction.victim_org_name
            signals = run_rule_extraction(article)
            new_victim = signals.get("victim_org_name")

            if new_victim == old_victim:
                continue

            print(f"\nArticle {article.id}: {article.title[:80]}")
            print(f"  victim: {old_victim!r} -> {new_victim!r}")

            save_extraction(article.id, signals)
            fixed_extractions += 1

            link = EventSourceLink.query.filter_by(raw_article_id=article.id).first()
            if not link:
                continue
            event = db.session.get(CyberEvent, link.cyber_event_id)
            if not event:
                continue
            if event.victim_org_name != new_victim:
                event.victim_org_name = new_victim
                event.victim_org_normalized = signals.get("victim_org_normalized")
                event.victim_display_label = signals.get("victim_display_label")
                event.victim_entity_type = signals.get("victim_entity_type")
                fixed_events += 1

        db.session.commit()
        print(f"\nUpdated extractions: {fixed_extractions}")
        print(f"Updated events:      {fixed_events}")


if __name__ == "__main__":
    main()
