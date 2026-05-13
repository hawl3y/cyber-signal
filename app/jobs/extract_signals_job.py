from app.models import RawArticle
from app.services.extraction import (
    get_ready_for_extraction,
    run_rule_extraction,
    save_extraction,
    mark_ready_for_clustering,
)


def extract_signals_job(force=False):
    """
    Entry point for MVP extraction stage.

    force=True re-runs extraction for already-processed live articles that have
    not been marked duplicate. Extraction is intentionally deterministic and
    single-path for the MVP.
    """
    if force:
        articles = RawArticle.query.filter(
            RawArticle.processing_status.in_(
                ["ready_for_extraction", "ready_for_clustering", "clustered"]
            ),
        ).all()
    else:
        articles = get_ready_for_extraction()

    for article in articles:
        signals = run_rule_extraction(article)
        save_extraction(article.id, signals)
        mark_ready_for_clustering(article)

    return True