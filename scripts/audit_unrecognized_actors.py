"""
Render a curator-friendly report from actor_candidate_sightings.

The pipeline's actor-audit stage scans articles every cron cycle and
writes any unrecognized capitalized phrase near attribution language to
this table. This script reads the table, filters out anything now in the
curated THREAT_ACTORS list (so adding a group makes its sightings
disappear from view), and prints a ranked report.

Usage:
  PYTHONPATH=. python scripts/audit_unrecognized_actors.py
  PYTHONPATH=. python scripts/audit_unrecognized_actors.py --days 7
  PYTHONPATH=. python scripts/audit_unrecognized_actors.py --min-mentions 3

Workflow:
  1. Curator runs this script periodically.
  2. Real groups in the output go into app/data/threat_actors.py.
  3. Re-run; added groups drop off (they're now in the known set).
  4. Live attribution picks them up on the next cron cycle.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

from app import create_app
from app.models import ActorCandidateSighting, RawArticle
from app.services.actor_candidate_audit import build_known_set, is_known


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=30,
                        help="Lookback window in days for sightings (default 30)")
    parser.add_argument("--min-mentions", type=int, default=2,
                        help="Only report candidates appearing in at least this many distinct articles (default 2)")
    parser.add_argument("--top", type=int, default=30,
                        help="Show at most this many candidates (default 30)")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=args.days)
        sightings = (
            ActorCandidateSighting.query
            .filter(ActorCandidateSighting.seen_at >= cutoff)
            .all()
        )

        if not sightings:
            print(f"No sightings recorded in last {args.days}d.")
            return

        known = build_known_set()
        # candidate -> { article_id: (source_name, title) }
        grouped = defaultdict(dict)
        for s in sightings:
            if is_known(s.candidate_name, known):
                continue
            article = RawArticle.query.get(s.raw_article_id)
            if not article:
                continue
            grouped[s.candidate_name][s.raw_article_id] = (
                article.source_name,
                (article.title or "")[:80],
            )

        if not grouped:
            print(
                f"All {len(sightings)} sightings in last {args.days}d already "
                "match the curated list. Nothing to review."
            )
            return

        ranked = sorted(
            grouped.items(),
            key=lambda item: (-len(item[1]), item[0].lower()),
        )
        ranked = [(name, hits) for name, hits in ranked if len(hits) >= args.min_mentions]
        ranked = ranked[: args.top]

        if not ranked:
            print(
                f"No unrecognized candidates with >= {args.min_mentions} "
                f"distinct article(s) in last {args.days}d."
            )
            return

        print(
            f"Unrecognized actor candidates (>= {args.min_mentions} distinct article(s), "
            f"last {args.days}d):"
        )
        print()
        for name, hits in ranked:
            print(f"  {name}    ({len(hits)} article{'s' if len(hits) != 1 else ''})")
            for _article_id, (source, title) in list(hits.items())[:3]:
                print(f"    [{source}] {title}")
            if len(hits) > 3:
                print(f"    ...and {len(hits) - 3} more")
            print()

        print("Real groups -> add to app/data/threat_actors.py with aliases and")
        print("actor_type. Re-run this audit afterwards to verify they drop off.")


if __name__ == "__main__":
    main()
