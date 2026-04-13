from app.services.processing import (
    clean_article,
    get_pending_articles,
    is_duplicate,
    mark_duplicate,
    mark_irrelevant,
    mark_ready_for_extraction,
    update_article,
)
def process_articles_job():
    """
    Entry point for article processing.
    """
    articles = get_pending_articles()

    for article in articles:
        if is_duplicate(article):
            mark_duplicate(article)
            continue

        cleaned_data = clean_article(article)
        update_article(article, cleaned_data)

        if not cleaned_data.get("is_relevant_incident", False):
            mark_irrelevant(article)
            continue

        mark_ready_for_extraction(article)

    return True