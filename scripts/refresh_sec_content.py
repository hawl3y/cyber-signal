"""
One-shot refresh: drop SEC RawArticles whose content is the legacy
templated stub ("Filed in a statement to investors. Direct primary-source
disclosure from the affected company under SEC reporting rules.") so the
next ingest re-creates them with the Item 1.05 prose now produced by
_fetch_sec_filing_document + _extract_cyber_disclosure_text.

Idempotent: SEC rows that already contain rich content pass through
untouched.

Run with:
  PYTHONPATH=. python scripts/refresh_sec_content.py
Then trigger an ingest cycle:
  PYTHONPATH=. python scripts/run_pipeline_once.py
"""
from app import create_app
from app.extensions import db
from app.models import (
    ArticleExtraction,
    CyberEvent,
    EventSourceLink,
    RawArticle,
)


TEMPLATE_MARKER = "Filed in a statement to investors."


def main():
    app = create_app()
    with app.app_context():
        sec_articles = RawArticle.query.filter_by(source_name="sec-edgar-cyber-8k").all()
        print(f"Local SEC articles: {len(sec_articles)}")

        stale = [a for a in sec_articles if TEMPLATE_MARKER in (a.content or "")]
        if not stale:
            print("All SEC articles already have rich content. Nothing to do.")
            return

        print(f"SEC articles with legacy templated content: {len(stale)}")
        for a in stale:
            print(f"  id={a.id}: {a.title}")

        ids = [a.id for a in stale]

        links = EventSourceLink.query.filter(
            EventSourceLink.raw_article_id.in_(ids)
        ).all()
        event_ids = list({link.cyber_event_id for link in links})

        EventSourceLink.query.filter(
            EventSourceLink.raw_article_id.in_(ids)
        ).delete(synchronize_session=False)

        ArticleExtraction.query.filter(
            ArticleExtraction.raw_article_id.in_(ids)
        ).delete(synchronize_session=False)

        deleted_events = 0
        for event_id in event_ids:
            remaining = EventSourceLink.query.filter_by(cyber_event_id=event_id).count()
            if remaining == 0:
                CyberEvent.query.filter_by(id=event_id).delete(synchronize_session=False)
                deleted_events += 1

        RawArticle.query.filter(RawArticle.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()
        print(
            f"Deleted: {len(stale)} articles, {deleted_events} events, "
            f"{len(links)} links."
        )
        print("Run scripts/run_pipeline_once.py to re-ingest with rich content.")


if __name__ == "__main__":
    main()
