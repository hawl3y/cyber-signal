"""
Force a one-shot enrichment pass over every event with fillable blanks,
ignoring the last_enriched_at idempotency guard. Used to seed
enrichment_audit_logs with a representative sample for the audit verdict
without waiting days for new events to trickle in.

Cost note: this re-runs AI on every event whose blanks _have_fillable_blanks
flagged. With Grok-4 web-search calls costing ~$0.20 each, a baseline pass
on ~10 events is roughly $1–$2.50.

Usage:
  PYTHONPATH=. python scripts/run_enrichment_audit_baseline.py

Then:
  PYTHONPATH=. python scripts/enrichment_audit_summary.py --days 1
"""
import json

from app import create_app
from app.services.event_enrichment import enrich_events


def main():
    app = create_app()
    with app.app_context():
        if not app.config.get("AI_ENRICHMENT_ENABLED"):
            print("AI_ENRICHMENT_ENABLED is false in this environment. Aborting.")
            return

        print("Forcing re-enrichment over all events with fillable blanks...")
        summary = enrich_events(force=True, max_workers=5)
        print("Done.")
        print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
