"""
Remove database rows that are no longer needed:
  - All RawArticle rows from source 'ransomware-live'
  - All RawArticle rows with processing_status = 'irrelevant'
    (they hold no extraction data and will never be reprocessed)

Safe to run any time.  Idempotent.

Usage:
    PYTHONPATH=. python scripts/cleanup_db.py
"""

import sys

sys.path.insert(0, ".")

from app import create_app
from app.extensions import db
from app.models import RawArticle


def main():
    app = create_app()
    with app.app_context():
        rl_count = RawArticle.query.filter_by(source_name="ransomware-live").count()
        irr_count = RawArticle.query.filter_by(processing_status="irrelevant").count()

        print(f"ransomware-live articles:  {rl_count}")
        print(f"irrelevant articles:       {irr_count}")
        print(f"total to delete:           {rl_count + irr_count}")

        if rl_count + irr_count == 0:
            print("Nothing to delete.")
            return

        confirm = input("\nDelete these rows? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

        deleted_rl = RawArticle.query.filter_by(source_name="ransomware-live").delete()
        deleted_irr = RawArticle.query.filter_by(processing_status="irrelevant").delete()
        db.session.commit()

        print(f"Deleted {deleted_rl} ransomware-live rows.")
        print(f"Deleted {deleted_irr} irrelevant rows.")


if __name__ == "__main__":
    main()
