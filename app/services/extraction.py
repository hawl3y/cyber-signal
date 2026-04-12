from app.models import RawArticle
from app.extensions import db

def get_ready_for_extraction():
    """
    Fetch articles ready for extraction.
    """
    return RawArticle.query.filter_by(processing_status="ready_for_extraction").all()


def run_rule_extraction(article):
    """
    Placeholder for rule-based extraction.
    """
    return {}


def run_ai_extraction(article):
    """
    Placeholder for AI-based extraction.
    """
    return {}


def merge_signals(rule_signals, ai_signals):
    """
    Placeholder for merging extraction results.
    """
    merged = {}
    merged.update(rule_signals)
    merged.update(ai_signals)
    return merged


def save_extraction(article_id, signals):
    """
    Placeholder for saving extracted signals.
    """
    return True


def mark_ready_for_clustering(article):
    """
    Mark article as ready for clustering.
    """
    article.processing_status = "ready_for_clustering"
    db.session.commit()
    return article