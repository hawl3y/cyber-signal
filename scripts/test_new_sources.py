"""
Fetch The Hacker News and NCSC feeds and run every article through the
processing filter. Shows pass/fail so noise patterns can be tuned before
deploying the new sources to production.
"""
import sys
sys.path.insert(0, ".")

import feedparser
from types import SimpleNamespace

from app.services.processing import is_relevant_incident
from app.services.extraction import run_rule_extraction
from app.utils.sources import get_source_config

SOURCES = [
    "the-hacker-news",
    "ncsc-uk",
]


def fetch_feed(url):
    feed = feedparser.parse(url)
    items = []
    for entry in feed.entries:
        items.append(SimpleNamespace(
            title=entry.get("title", ""),
            summary=entry.get("summary", ""),
            content=(entry.get("content", [{}])[0].get("value", "")
                     if entry.get("content") else ""),
            source_name=None,
        ))
    return items


def main():
    for source_name in SOURCES:
        source = get_source_config(source_name)
        url = source["url"]
        print(f"\n{'='*70}")
        print(f"SOURCE: {source['display_label']}  ({url})")
        print(f"{'='*70}")

        articles = fetch_feed(url)
        passed, failed = [], []

        for a in articles:
            a.source_name = source_name
            if is_relevant_incident(a):
                passed.append(a)
            else:
                failed.append(a)

        print(f"\nPASSED ({len(passed)}/{len(articles)}):")
        for a in passed:
            signals = run_rule_extraction(a)
            victim = signals.get("victim_org_name") or "-"
            attack = signals.get("attack_type") or "-"
            print(f"  [victim={victim:<25} attack={attack:<20}] {a.title[:65]}")

        print(f"\nFILTERED OUT ({len(failed)}/{len(articles)}):")
        for a in failed:
            print(f"  {a.title[:75]}")


if __name__ == "__main__":
    main()
