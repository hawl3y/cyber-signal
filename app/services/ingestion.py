from app.extensions import db
from app.models import RawArticle

def fetch_source_items(source):
    """
    Placeholder for fetching items from a source.
    """
    return []

def normalize_article(item):
    """
    Placeholder for normalizing raw source data into article structure.
    """
    return {}

def save_raw_article(article):
    """
    Save a normalized article to the database.
    """
    raw_article = RawArticle(
        source_type=article.get("source_type"),
        source_name=article.get("source_name"),
        source_url=article.get("source_url"),
        publisher=article.get("publisher"),
        article_url=article.get("article_url"),
        title=article.get("title"),
        normalized_title=article.get("normalized_title"),
        summary=article.get("summary"),
        content=article.get("content"),
        normalized_domain=article.get("normalized_domain"),
        ingestion_batch_id=article.get("ingestion_batch_id"),
        published_at=article.get("published_at"),
        fetched_at=article.get("fetched_at"),
        content_hash=article.get("content_hash"),
        title_hash=article.get("title_hash"),
        language=article.get("language"),
        is_duplicate=article.get("is_duplicate", False),
        duplicate_of_article_id=article.get("duplicate_of_article_id"),
        processing_status=article.get("processing_status"),
    )

    db.session.add(raw_article)
    db.session.commit()

    return raw_article