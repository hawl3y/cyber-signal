"""
Reset CISA KEV articles that were rejected by the old relevance filter back to pending.
Safe to run repeatedly. Run AFTER deploying the processing.py CISA KEV fix.

Run: PYTHONPATH=. python scripts/reset_irrelevant_kev.py
"""
from app import create_app
from app.extensions import db
from app.models import RawArticle

app = create_app()
with app.app_context():
    kev_articles = RawArticle.query.filter_by(
        source_name="cisa-kev",
        processing_status="irrelevant",
    ).all()

    print(f"Resetting {len(kev_articles)} CISA KEV articles to pending...")
    for a in kev_articles:
        a.processing_status = "pending"
    db.session.commit()
    print("Done. Run the full pipeline next:")
    print("  PYTHONPATH=. python scripts/run_pipeline_once.py")
