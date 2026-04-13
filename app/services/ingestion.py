import re
from datetime import datetime
from html import unescape

import feedparser

from app.extensions import db
from app.models import RawArticle


def _clean_html_text(value):
    """
    Strip HTML tags and normalize whitespace from feed content.
    """
    if not value:
        return ""

    text = unescape(value)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def fetch_source_items(source):
    """
    Fetch and normalize raw RSS items from a configured source.
    """
    feed = feedparser.parse(source.get("url"))
    fetched_at = datetime.utcnow()
    ingestion_batch_id = fetched_at.strftime("%Y%m%d%H%M%S")
    items = []

    for entry in feed.entries:
        article_url = (
            entry.get("link")
            or entry.get("id")
        )
        title = _clean_html_text(entry.get("title", ""))
        summary = _clean_html_text(entry.get("summary", ""))

        if not article_url or not title:
            continue

        published_at = fetched_at
        if entry.get("published_parsed"):
            published_at = datetime(*entry.published_parsed[:6])

        items.append(
            {
                "source_type": source.get("type"),
                "source_name": source.get("name"),
                "source_url": source.get("url"),
                "publisher": _clean_html_text(feed.feed.get("title") or source.get("name")),
                "article_url": article_url,
                "title": title,
                "normalized_title": title.lower().strip(),
                "summary": summary,
                "content": summary,
                "normalized_domain": source.get("url", "").replace("https://", "").replace("http://", "").split("/")[0],
                "ingestion_batch_id": ingestion_batch_id,
                "published_at": published_at,
                "fetched_at": fetched_at,
                "language": "en",
                "processing_status": "pending",
            }
        )

    return items


def normalize_article(item):
    """
    Pass-through normalization for now.
    """
    return item


def save_raw_article(article):
    """
    Save a normalized article to the database if it does not already exist.
    """
    existing = RawArticle.query.filter_by(article_url=article.get("article_url")).first()
    if existing:
        return existing

    raw_article = RawArticle(**article)

    db.session.add(raw_article)
    db.session.commit()

    return raw_article