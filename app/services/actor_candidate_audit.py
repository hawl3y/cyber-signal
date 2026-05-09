"""
Shared logic for the threat-actor-candidate audit pipeline.

  - The cron stage (actor_candidate_audit_job) calls scan_articles() to
    find unrecognized candidates near attribution language and persists
    them to actor_candidate_sightings.
  - The CLI (scripts/audit_unrecognized_actors.py) reads the persisted
    sightings and renders a human-friendly report for the curator.

The candidate-finding logic, stop-word list, and known-actor lookup live
here so both consumers stay consistent.
"""
import re

from app.data.threat_actors import THREAT_ACTORS


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

CANDIDATE_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9$]*(?:\s+[A-Z][A-Za-z0-9$]*){0,3})\b"
)

STOP_WORDS = {
    # Government / law-enforcement
    "fbi", "cisa", "dhs", "nsa", "gchq", "interpol", "europol", "doj", "irs",
    "fda", "ftc", "sec", "treasury", "state department", "pentagon",
    "white house", "department of defense", "department of homeland security",
    "ministry", "department",
    # Country / region / nationality
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
    # Publishers / outlets
    "bleepingcomputer", "krebsonsecurity", "krebs on security",
    "the record", "the recorded future", "recorded future news",
    "the hacker news", "thehackernews", "wired", "reuters", "bloomberg",
    "associated press", "ap", "ap news", "techcrunch", "ars technica",
    "cnn", "nbc", "abc", "cbs", "bbc", "nyt", "washington post",
    # Generic
    "the company", "the group", "the organization", "the attackers",
    "the hackers", "the victim", "the team", "the gang",
    "ransomware", "malware", "phishing", "incident", "breach",
    "intelligence", "intel", "threat intelligence",
    "cve", "cvss", "vulnerability", "exploit", "advisory",
    "researchers", "researcher", "investigators", "investigator",
    "vendor", "company", "attack", "hackers", "internet", "campaign",
    "chaos",
    "file system driver", "out-of-bounds", "buffer overflow",
    # Sentence-start common words
    "the", "a", "an", "according", "officials", "officials said",
    "data", "information", "users", "customers",
    "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
}


def build_known_set():
    """Lowercased canonical names + aliases from THREAT_ACTORS."""
    known = set()
    for canonical, info in THREAT_ACTORS.items():
        known.add(canonical.lower())
        for alias in info.get("aliases", []) or []:
            known.add(alias.lower())
    return known


def is_stop_word(candidate):
    return candidate.lower() in STOP_WORDS


def is_known(candidate, known_set):
    return candidate.lower() in known_set


def find_candidates_in_text(text):
    """
    Return list of unique candidate strings near attribution language.
    Each capitalized phrase appears at most once per article (caller
    handles further dedup).
    """
    if not text:
        return []

    seen = set()
    candidates = []
    for match in ATTRIBUTION_RE.finditer(text):
        start = max(0, match.start() - 80)
        end = min(len(text), match.end() + 80)
        window = text[start:end]
        for cand_match in CANDIDATE_RE.finditer(window):
            candidate = cand_match.group(1).strip()
            if not candidate or len(candidate) < 3:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def candidate_context(text, candidate, window=120):
    """
    Return a short context excerpt around the first occurrence of the
    candidate in text, suitable for storing alongside the sighting.
    """
    if not text or not candidate:
        return None
    idx = text.lower().find(candidate.lower())
    if idx < 0:
        return None
    start = max(0, idx - window)
    end = min(len(text), idx + len(candidate) + window)
    snippet = text[start:end]
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return snippet
