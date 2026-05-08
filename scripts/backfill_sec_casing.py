"""
One-shot backfill: title-case all-caps company names ingested from SEC EDGAR
before the casing fix landed. Touches only sec-edgar-cyber-8k source so other
sources are unaffected.

Updates raw_articles (title, summary, content, normalized_title),
article_extractions (victim_org_name, victim_display_label),
and cyber_events (canonical_title, victim_org_name, victim_display_label).

Run with: PYTHONPATH=. python scripts/backfill_sec_casing.py
"""
from app import create_app
from app.extensions import db
from app.models import RawArticle, ArticleExtraction, CyberEvent, EventSourceLink
from app.services.ingestion import _title_case_company_name


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
        title = article.title or ""
        if " discloses" not in title:
            continue

        old_company = title.split(" discloses", 1)[0]
        new_company = _title_case_company_name(old_company)
        if new_company == old_company:
            continue

        article.title = title.replace(old_company, new_company, 1)
        article.normalized_title = (article.title or "").lower().strip()
        if article.summary:
            article.summary = article.summary.replace(old_company, new_company)
        if article.content:
            article.content = article.content.replace(old_company, new_company)
        fixed_articles += 1

        extraction = ArticleExtraction.query.filter_by(raw_article_id=article.id).first()
        if extraction:
            if extraction.victim_org_name == old_company:
                extraction.victim_org_name = new_company
            if extraction.victim_display_label == old_company:
                extraction.victim_display_label = new_company
            fixed_extractions += 1

        links = EventSourceLink.query.filter_by(raw_article_id=article.id).all()
        for link in links:
            event = CyberEvent.query.get(link.cyber_event_id)
            if not event:
                continue
            if event.victim_org_name == old_company:
                event.victim_org_name = new_company
            if event.victim_display_label == old_company:
                event.victim_display_label = new_company
            if event.canonical_title and old_company in event.canonical_title:
                event.canonical_title = event.canonical_title.replace(old_company, new_company, 1)
            fixed_events += 1

    db.session.commit()
    print(
        f"Backfilled SEC casing: {fixed_articles} articles, "
        f"{fixed_extractions} extractions, {fixed_events} events."
    )
