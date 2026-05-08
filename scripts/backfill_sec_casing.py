"""
One-shot backfill: regenerate SEC EDGAR article/event text from the canonical
template using the cleaned company name. This rebuilds fields from scratch so
prior partial backfill runs that produced corrupted casing (e.g. 'Sec' instead
of 'SEC') are fully repaired in one pass.

Idempotent: running twice produces the same result. Touches only the
sec-edgar-cyber-8k source so other sources are unaffected.

Run with: PYTHONPATH=. python scripts/backfill_sec_casing.py
"""
from app import create_app
from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink
from app.services.ingestion import _title_case_company_name


def _company_from_title(title):
    if not title:
        return None
    if " discloses" in title:
        return title.split(" discloses", 1)[0]
    return None


app = create_app()

with app.app_context():
    sec_articles = RawArticle.query.filter_by(source_name="sec-edgar-cyber-8k").all()
    if not sec_articles:
        print("No SEC EDGAR articles to backfill.")
        raise SystemExit

    fixed_articles = 0
    fixed_extractions = 0
    fixed_events = 0

    for article in sec_articles:
        old_company = _company_from_title(article.title)
        if not old_company:
            extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()
            if extraction and extraction.victim_org_name:
                old_company = extraction.victim_org_name
            else:
                continue

        company_name = _title_case_company_name(old_company)
        file_date = article.published_at.strftime("%Y-%m-%d") if article.published_at else "unknown"

        new_title = f"{company_name} discloses breach in SEC 8-K filing"
        new_summary = (
            f"{company_name} disclosed a data breach in a Form 8-K filing "
            f"with the SEC on {file_date}. Filed in a statement to investors. "
            f"Direct primary-source disclosure from the affected company "
            f"under SEC reporting rules."
        )

        article.title = new_title
        article.summary = new_summary
        article.content = new_summary
        article.normalized_title = new_title.lower().strip()
        fixed_articles += 1

        extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()
        if extraction:
            extraction.victim_org_name = company_name
            extraction.victim_display_label = company_name
            extraction.short_event_summary = new_summary
            fixed_extractions += 1

        for link in EventSourceLink.query.filter_by(raw_article_id=article.id).all():
            event = CyberEvent.query.get(link.cyber_event_id)
            if not event:
                continue
            event.victim_org_name = company_name
            event.victim_display_label = company_name
            event.canonical_title = new_title
            event.summary_short = new_summary
            fixed_events += 1

    db.session.commit()
    print(
        f"Backfilled SEC casing: {fixed_articles} articles, "
        f"{fixed_extractions} extractions, {fixed_events} events."
    )
