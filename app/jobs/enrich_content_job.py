from app.services.ingestion import enrich_article_content


def enrich_content_job():
    return enrich_article_content()
