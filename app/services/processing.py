from app.extensions import db
from app.models import RawArticle


def get_pending_articles():
    """
    Fetch articles waiting for processing.
    """
    return RawArticle.query.filter_by(processing_status="pending").all()


def is_duplicate(article):
    """
    Placeholder for duplicate detection logic.
    """
    return False


def mark_duplicate(article):
    """
    Mark an article as duplicate.
    """
    article.is_duplicate = True
    article.processing_status = "duplicate"
    db.session.commit()
    return article


def clean_article(article):
    """
    Placeholder for article cleaning and normalization updates.
    """
    return article


def update_article(article, cleaned_data):
    """
    Apply cleaned data to an article.
    """
    # no-op for now, structure in place for future updates
    db.session.commit()
    return article


def mark_ready_for_extraction(article):
    """
    Mark article as ready for extraction.
    """
    article.processing_status = "ready_for_extraction"
    db.session.commit()
    return article