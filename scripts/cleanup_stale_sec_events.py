"""
One-shot cleanup: drop SEC-EDGAR events that were ingested before the
"items must contain 1.05" filter landed. Re-queries EDGAR for the current
list of valid 1.05 filings within the 60-day window and deletes any local
SEC RawArticle whose accession is not in that set (along with its
extraction, event, and links).

Idempotent: re-running has no effect once the DB matches the current
EDGAR truth set.

Run with: PYTHONPATH=. python scripts/cleanup_stale_sec_events.py
"""
import re
import requests

from app import create_app
from app.extensions import db
from app.models import (
    ArticleExtraction,
    CyberEvent,
    EventSourceLink,
    RawArticle,
)
from flask import current_app


def _accession_from_url(url):
    if not url:
        return None
    match = re.search(r"/(\d{10}-\d{2}-\d{6})", url)
    if match:
        return match.group(1)
    match = re.search(r"/(\d{18})/", url)
    if match:
        digits = match.group(1)
        return f"{digits[:10]}-{digits[10:12]}-{digits[12:]}"
    return None


def _fetch_valid_1_05_accessions(user_agent):
    response = requests.get(
        "https://efts.sec.gov/LATEST/search-index",
        params={
            "q": '"material cybersecurity incident"',
            "forms": "8-K",
            "size": 100,
        },
        headers={"User-Agent": user_agent},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()

    valid = set()
    for hit in data.get("hits", {}).get("hits", []):
        src = hit.get("_source", {}) or {}
        items = src.get("items") or []
        adsh = src.get("adsh")
        if adsh and "1.05" in items:
            valid.add(adsh)
    return valid


def main():
    app = create_app()
    with app.app_context():
        user_agent = current_app.config.get(
            "SEC_USER_AGENT", "Cyber Signal cyber-signal@example.com"
        )

        valid = _fetch_valid_1_05_accessions(user_agent)
        print(f"Valid 1.05 accessions returned by EDGAR: {len(valid)}")

        sec_articles = RawArticle.query.filter_by(source_name="sec-edgar-cyber-8k").all()
        print(f"Local SEC articles: {len(sec_articles)}")

        stale = []
        for article in sec_articles:
            accession = _accession_from_url(article.article_url)
            if accession is None or accession not in valid:
                stale.append(article)

        if not stale:
            print("Nothing to clean up.")
            return

        print(f"Stale SEC articles to remove: {len(stale)}")
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
        print(f"Deleted: {len(stale)} articles, {deleted_events} events, {len(links)} links")


if __name__ == "__main__":
    main()
