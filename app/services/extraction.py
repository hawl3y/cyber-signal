from app.extensions import db
from app.models import RawArticle, ArticleExtraction


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
    Merge extraction results.
    """
    merged = {}
    merged.update(rule_signals)
    merged.update(ai_signals)
    return merged


def save_extraction(article_id, signals):
    """
    Save extracted signals to the database.
    """
    extraction = ArticleExtraction(
        raw_article_id=article_id,
        victim_org_name=signals.get("victim_org_name"),
        victim_org_normalized=signals.get("victim_org_normalized"),
        industry=signals.get("industry"),
        region=signals.get("region"),
        country=signals.get("country"),
        city=signals.get("city"),
        attack_type=signals.get("attack_type"),
        access_vector=signals.get("access_vector"),
        impact_type=signals.get("impact_type"),
        actor_name=signals.get("actor_name"),
        actor_type=signals.get("actor_type"),
        attribution_status=signals.get("attribution_status"),
        vuln_status=signals.get("vuln_status"),
        cve_ids=signals.get("cve_ids"),
        zero_day_flag=signals.get("zero_day_flag", False),
        short_event_summary=signals.get("short_event_summary"),
        extracted_signals=signals,
        extraction_confidence=signals.get("extraction_confidence"),
    )

    db.session.add(extraction)
    db.session.commit()
    return extraction


def mark_ready_for_clustering(article):
    """
    Mark article as ready for clustering.
    """
    article.processing_status = "ready_for_clustering"
    db.session.commit()
    return article