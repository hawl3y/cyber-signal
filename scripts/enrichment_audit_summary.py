"""
Print an aggregated view of recent EnrichmentAuditLog entries so we can
decide whether AI enrichment is worth the spend.

For each audited field the report shows:
  ALREADY  — events where the field was already populated before AI ran
  FILLED   — events where AI added a real value to a previously blank field
  REDUNDANT — events where AI returned a value but the field was already populated
  BLANK    — events where the field stayed blank after AI ran (no value added)

Plus per-call cost (duration, tokens, web-search calls) and failure rate.

Usage:
  PYTHONPATH=. python scripts/enrichment_audit_summary.py
  PYTHONPATH=. python scripts/enrichment_audit_summary.py --days 7
"""
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

from app import create_app
from app.models import EnrichmentAuditLog


AUDITED_FIELDS = (
    "victim_org_name",
    "industry",
    "attack_type",
    "actor_name",
    "actor_type",
    "attribution_status",
    "country",
    "region",
    "summary_short",
)


def _is_blank(value):
    if value is None:
        return True
    if isinstance(value, str) and (not value.strip() or value.strip().lower() == "unknown"):
        return True
    return False


def _has_value(value):
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def _classify(field, before, after, returned):
    """Return one of: already, filled, redundant, blank."""
    prev = (before or {}).get(field)
    new = (after or {}).get(field)
    ai_ret = (returned or {}).get(field)

    was_blank = _is_blank(prev)

    if not was_blank:
        if _has_value(ai_ret) and not _is_blank(ai_ret):
            return "redundant"
        return "already"

    if not _is_blank(new) and prev != new:
        return "filled"

    return "blank"


def _accumulate_usage(totals, usage):
    if not usage:
        return
    for k, v in usage.items():
        if isinstance(v, (int, float)):
            totals[k] = totals.get(k, 0) + v


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=7, help="Lookback window in days (default 7)")
    args = parser.parse_args()

    cutoff = datetime.utcnow() - timedelta(days=args.days)
    app = create_app()
    with app.app_context():
        rows = (
            EnrichmentAuditLog.query
            .filter(EnrichmentAuditLog.started_at >= cutoff)
            .order_by(EnrichmentAuditLog.started_at.desc())
            .all()
        )

        if not rows:
            print(f"No enrichment audit logs in last {args.days}d.")
            return

        per_field = {field: {"already": 0, "filled": 0, "redundant": 0, "blank": 0} for field in AUDITED_FIELDS}

        article_calls = 0
        web_calls = 0
        failures = 0
        total_duration_ms = 0
        article_usage_totals = defaultdict(int)
        web_usage_totals = defaultdict(int)

        for row in rows:
            for field in AUDITED_FIELDS:
                # Combine article + web returns: AI "returned" a value if
                # either call did.
                merged_returned = {}
                if row.article_returned:
                    merged_returned.update(row.article_returned)
                if row.web_returned:
                    for k, v in row.web_returned.items():
                        if not _is_blank(v):
                            merged_returned[k] = v

                bucket = _classify(field, row.fields_before, row.fields_after, merged_returned)
                per_field[field][bucket] += 1

            if row.article_called:
                article_calls += 1
            if row.web_called:
                web_calls += 1
            if row.error:
                failures += 1
            if row.duration_ms:
                total_duration_ms += row.duration_ms

            _accumulate_usage(article_usage_totals, row.article_usage)
            _accumulate_usage(web_usage_totals, row.web_usage)

        total_runs = len(rows)
        avg_duration_ms = total_duration_ms // total_runs if total_runs else 0

        print(f"Enrichment audit — last {args.days}d ({cutoff.isoformat()}Z onward)")
        print(f"Runs: {total_runs}  article_calls: {article_calls}  web_calls: {web_calls}  failures: {failures}")
        print(f"Avg duration: {avg_duration_ms} ms/event")
        print()
        print("Token usage (article-only call):")
        if article_usage_totals:
            for k, v in sorted(article_usage_totals.items()):
                print(f"  {k}: {v}")
        else:
            print("  (none)")
        print()
        print("Token usage (web-search call):")
        if web_usage_totals:
            for k, v in sorted(web_usage_totals.items()):
                print(f"  {k}: {v}")
        else:
            print("  (none)")
        print()

        header = f"{'field':<22}  {'already':>7}  {'filled':>6}  {'redundant':>9}  {'blank':>5}"
        print(header)
        print("-" * len(header))
        for field in AUDITED_FIELDS:
            stats = per_field[field]
            print(
                f"{field:<22}  {stats['already']:>7}  {stats['filled']:>6}  "
                f"{stats['redundant']:>9}  {stats['blank']:>5}"
            )

        print()
        print("Read this as:")
        print("  filled    > 0 → AI is adding value here (keep)")
        print("  redundant > 0 → AI is doing wasted work (deterministic side already had it)")
        print("  blank dominates → AI cannot help here either (kill or accept the gap)")


if __name__ == "__main__":
    main()
