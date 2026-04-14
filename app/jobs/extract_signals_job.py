from app.models import RawArticle
from app.services.extraction import (
    get_ready_for_extraction,
    run_rule_extraction,
    run_ai_extraction,
    merge_signals,
    save_extraction,
    mark_ready_for_clustering,
)


def extract_signals_job(force=False):
    """
    Entry point for extraction stage.

    force=True should re-run extraction for articles that already passed
    processing, not for every non-duplicate raw article.
    """
    if force:
        articles = RawArticle.query.filter(
            RawArticle.is_duplicate.is_(False),
            RawArticle.processing_status.in_(
                ["ready_for_extraction", "ready_for_clustering", "clustered"]
            ),
        ).all()
    else:
        articles = get_ready_for_extraction()

    for article in articles:
        rule_signals = run_rule_extraction(article)
        ai_signals = run_ai_extraction(article)

        merged = merge_signals(rule_signals, ai_signals)

        save_extraction(article.id, merged)
        mark_ready_for_clustering(article)

    return True