"""
Surface threat-actor candidates from recent article text that are not in
the curated THREAT_ACTORS list. Helps maintain the deterministic actor
recognition pipeline:

  1. Run periodically (e.g. weekly).
  2. Inspect output.
  3. Add real groups to app/data/threat_actors.py.

The script searches a window around attribution language ("claimed
responsibility", "linked to", "behind the attack", etc.) for capitalized
phrases. Anything already covered by the curated list (canonical name or
alias, case-insensitive) is filtered out, as are common non-actor
capitalized terms (FBI, CISA, country names, vendor names, publishers).

Usage:
  PYTHONPATH=. python scripts/audit_unrecognized_actors.py
  PYTHONPATH=. python scripts/audit_unrecognized_actors.py --days 30
  PYTHONPATH=. python scripts/audit_unrecognized_actors.py --min-mentions 2
"""
import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta

from app import create_app
from app.data.threat_actors import THREAT_ACTORS
from app.models import RawArticle


# Phrases that signal an actor is being named in nearby text.
ATTRIBUTION_RE = re.compile(
    r"\b(?:"
    r"claim(?:s|ed)?\s+(?:responsibility|credit|they|to\s+have|the\s+attack|the\s+breach)|"
    r"link(?:s|ed)\s+to|"
    r"tie(?:s|d)\s+to|"
    r"attributed\s+to|"
    r"associated\s+with|"
    r"behind\s+the\s+(?:attack|breach|campaign|intrusion)|"
    r"the\s+work\s+of|"
    r"operated\s+by|"
    r"believed\s+to\s+be|"
    r"suspected\s+to\s+be|"
    r"named\s+on\s+(?:its|their)\s+leak\s+site|"
    r"posted\s+on\s+(?:its|their)\s+leak\s+site|"
    r"added\s+(?:the\s+\w+\s+)?to\s+(?:its|their)\s+leak\s+site|"
    r"ransomware\s+(?:gang|group|operator)|"
    r"threat\s+(?:actor|group)|"
    r"hacking\s+group|"
    r"hacker\s+group|"
    r"cyber(?:criminal|criminal\s+gang)|"
    r"hacktivist\s+(?:group|collective)|"
    r"state-sponsored|"
    r"nation-state\s+(?:actor|group)"
    r")\b",
    flags=re.IGNORECASE,
)

# Capitalized phrase candidate: 1-4 tokens, each starts with capital letter.
# Tolerates digits and $ (Lapsus$, FIN7).
CANDIDATE_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9$]*(?:\s+[A-Z][A-Za-z0-9$]*){0,3})\b"
)

# Common capitalized phrases that aren't threat actors. Lowercase form.
STOP_WORDS = {
    # Government / law-enforcement
    "fbi", "cisa", "dhs", "nsa", "gchq", "interpol", "europol", "doj", "irs",
    "fda", "ftc", "sec", "treasury", "state department", "pentagon",
    "white house", "department of defense", "department of homeland security",
    "ministry", "department",
    # Country / region / nationality (incl. generic "X APT" / "X hackers")
    "united states", "u.s.", "us", "usa", "uk", "u.k.", "eu",
    "european union", "north america", "south america", "asia",
    "europe", "africa", "middle east", "asia-pacific",
    "china", "russia", "iran", "north korea", "ukraine", "germany",
    "france", "japan", "india", "israel", "australia", "canada",
    "south korea", "saudi arabia", "vietnam", "iraq", "syria",
    "iranian", "russian", "chinese", "north korean", "ukrainian",
    "iranian apt", "russian apt", "chinese apt", "north korean apt",
    "iranian hackers", "russian hackers", "chinese hackers",
    # Vendor / tech / common cyber product names
    "microsoft", "google", "apple", "amazon", "meta", "facebook",
    "twitter", "x", "tiktok", "salesforce", "oracle", "ibm", "intel",
    "cisco", "vmware", "aws", "azure", "windows", "linux", "android",
    "ios", "github", "openai", "anthropic", "nvidia", "tesla",
    "f5", "big-ip", "big", "ip", "apm", "ip apm", "bigip",
    "fortinet", "fortigate", "palo alto", "checkpoint", "check point",
    "trellix", "crowdstrike", "sentinelone", "sophos", "kaspersky",
    "mandiant", "okta", "cloudflare", "akamai", "zscaler", "snowflake",
    "instructure", "canvas",
    # Publishers / outlets that show up in cyber news
    "bleepingcomputer", "krebsonsecurity", "krebs on security",
    "the record", "the recorded future", "recorded future news",
    "the hacker news", "thehackernews", "wired", "reuters", "bloomberg",
    "associated press", "ap", "ap news", "techcrunch", "ars technica",
    "cnn", "nbc", "abc", "cbs", "bbc", "nyt", "washington post",
    # Generic security / news terms
    "the company", "the group", "the organization", "the attackers",
    "the hackers", "the victim", "the team", "the gang",
    "ransomware", "malware", "phishing", "incident", "breach",
    "intelligence", "intel", "threat intelligence",
    "cve", "cvss", "vulnerability", "exploit", "advisory",
    "researchers", "researcher", "investigators", "investigator",
    "vendor", "company", "attack", "hackers", "internet", "campaign",
    "chaos",  # Chaos ransomware mentioned as cover, not the actor
    "file system driver", "out-of-bounds", "buffer overflow",
    # Common words that capitalize at sentence start
    "the", "a", "an", "according", "officials", "officials said",
    "data", "information", "users", "customers",
    "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
}


def _build_known_set():
    """Lowercased set of canonical names + aliases from the curated list."""
    known = set()
    for canonical, info in THREAT_ACTORS.items():
        known.add(canonical.lower())
        for alias in info.get("aliases", []) or []:
            known.add(alias.lower())
    return known


def _is_stop_word(candidate):
    return candidate.lower() in STOP_WORDS


def _is_known(candidate, known_set):
    return candidate.lower() in known_set


def _find_candidates_in_text(text):
    """Return list of candidate strings found near attribution language."""
    if not text:
        return []

    candidates = []
    for match in ATTRIBUTION_RE.finditer(text):
        # Window: 80 chars before, 80 after
        start = max(0, match.start() - 80)
        end = min(len(text), match.end() + 80)
        window = text[start:end]
        for cand_match in CANDIDATE_RE.finditer(window):
            candidate = cand_match.group(1).strip()
            if not candidate:
                continue
            # Drop single-character noise
            if len(candidate) < 3:
                continue
            candidates.append(candidate)
    return candidates


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=30,
                        help="Lookback window in days (default 30)")
    parser.add_argument("--min-mentions", type=int, default=2,
                        help="Only report candidates appearing in at least this many distinct articles (default 2)")
    parser.add_argument("--top", type=int, default=30,
                        help="Show at most this many candidates (default 30)")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=args.days)
        articles = (
            RawArticle.query
            .filter(RawArticle.created_at >= cutoff)
            .all()
        )
        print(f"Scanning {len(articles)} articles from last {args.days}d...")

        known = _build_known_set()
        # candidate -> { article_id: (source_name, title_excerpt) }
        # Map keyed by article_id so each article counts at most once.
        sightings = defaultdict(dict)

        for article in articles:
            text = " ".join([
                article.title or "",
                article.summary or "",
                article.content or "",
            ])
            seen_in_this_article = set()
            for candidate in _find_candidates_in_text(text):
                if _is_stop_word(candidate):
                    continue
                if _is_known(candidate, known):
                    continue
                if candidate in seen_in_this_article:
                    continue
                seen_in_this_article.add(candidate)
                sightings[candidate][article.id] = (
                    article.source_name,
                    (article.title or "")[:80],
                )

        if not sightings:
            print("\nNo unrecognized actor candidates found.")
            return

        ranked = sorted(
            sightings.items(),
            key=lambda item: (-len(item[1]), item[0].lower()),
        )
        ranked = [(name, hits) for name, hits in ranked if len(hits) >= args.min_mentions]
        ranked = ranked[: args.top]

        if not ranked:
            print(f"\nNo unrecognized candidates with >= {args.min_mentions} distinct article(s).")
            return

        print(f"\nUnrecognized actor candidates (>= {args.min_mentions} distinct article(s)):")
        print()
        for name, hits in ranked:
            print(f"  {name}    ({len(hits)} article{'s' if len(hits) != 1 else ''})")
            for article_id, (source, title) in list(hits.items())[:3]:
                print(f"    [{source}] {title}")
            if len(hits) > 3:
                print(f"    ...and {len(hits) - 3} more")
            print()

        print("Real groups -> add to app/data/threat_actors.py with aliases and")
        print("actor_type. Re-run this audit afterwards to verify they drop off.")


if __name__ == "__main__":
    main()
