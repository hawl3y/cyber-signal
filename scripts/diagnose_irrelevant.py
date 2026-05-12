"""
Audit the 107 irrelevant articles to understand why they were rejected.
Run: PYTHONPATH=. python scripts/diagnose_irrelevant.py
"""
from collections import defaultdict
from app import create_app
from app.models import RawArticle

app = create_app()
with app.app_context():
    articles = RawArticle.query.filter_by(processing_status="irrelevant").all()
    print(f"Total irrelevant: {len(articles)}\n")

    by_source = defaultdict(list)
    for a in articles:
        by_source[a.source_name].append(a)

    print("=== BY SOURCE ===")
    for source, arts in sorted(by_source.items(), key=lambda x: -len(x[1])):
        enriched = sum(1 for a in arts if a.content_enriched)
        print(f"  {source}: {len(arts)} articles ({enriched} enriched, {len(arts)-enriched} unenriched)")
    print()

    print("=== UNENRICHED ARTICLES (enrichment blocked) ===")
    unenriched = [a for a in articles if not a.content_enriched]
    print(f"  Total unenriched: {len(unenriched)}\n")
    for a in sorted(unenriched, key=lambda x: x.source_name):
        content_len = len(a.content or "")
        print(f"  [{a.source_name}] {a.title}")
        print(f"    summary len={len(a.summary or '')} content len={content_len}")
    print()

    print("=== ENRICHED BUT IRRELEVANT (genuinely rejected) ===")
    enriched_irrelevant = [a for a in articles if a.content_enriched]
    print(f"  Total: {len(enriched_irrelevant)}\n")
    for a in sorted(enriched_irrelevant, key=lambda x: x.source_name)[:30]:
        print(f"  [{a.source_name}] {a.title}")
