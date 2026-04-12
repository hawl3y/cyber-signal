from app.services.extraction import (
    get_ready_for_extraction,
    run_rule_extraction,
    run_ai_extraction,
    merge_signals,
    save_extraction,
    mark_ready_for_clustering,
)


def extract_signals_job():
    """
    Entry point for extraction stage.
    """
    articles = get_ready_for_extraction()

    for article in articles:
        rule_signals = run_rule_extraction(article)
        ai_signals = run_ai_extraction(article)

        merged = merge_signals(rule_signals, ai_signals)

        save_extraction(article.id, merged)
        mark_ready_for_clustering(article)

    return True