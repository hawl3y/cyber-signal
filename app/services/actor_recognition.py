"""
Deterministic threat-actor attribution.

Replaces the AI enrichment service's actor work with a pattern match against
the curated knowledge base in app/data/threat_actors.py. Runs after
clustering: for each event with a victim and no (or generic) actor, scan
the combined text of all linked articles for any actor name or alias.
If matched, also classify attribution_status from the surrounding context.

Aligned with the project rules:
  - signal_type=activity events are skipped (never get actors)
  - victim_org_name must be set (no victim → no actor)
  - already-attributed events are skipped unless the existing name is generic
"""
import re
from datetime import datetime

from app.data.threat_actors import THREAT_ACTORS
from app.extensions import db
from app.models import CyberEvent, EventSourceLink, RawArticle
from app.services.clustering import recompute_high_impact

# Short single-word aliases (≤5 alphabetic chars) are common English words
# (Play, Hive, Maze, FOG, Royal, Snake …) and must appear near explicit
# actor-class language to prevent matches on brand names / product names
# (e.g. "Play" matching "Google Play Store").
_ACTOR_CLASS_CONTEXT_RE = re.compile(
    r"\b(?:"
    r"ransomware|threat\s+(?:group|actor|actors|campaign)|"
    r"hacking\s+(?:group|gang|crew)|cybercriminal|criminal\s+(?:group|gang)|"
    r"hackers|hacktivist|nation.state|apt\b|cyber\s+(?:gang|group|crew)|"
    r"gang|crew"
    r")\b",
    re.IGNORECASE,
)


def _alias_requires_actor_context(alias_name):
    """Return True if the alias is short enough that it needs nearby actor-class
    language to be a valid match (prevents common-word false positives)."""
    return (
        len(alias_name) <= 5
        and alias_name.replace("-", "").isalpha()
        and " " not in alias_name
    )


# Temporal markers that indicate an actor mention is a reference to a past/different
# incident rather than the current one. When these appear in the text immediately
# before an actor name in the attribution window, the match is suppressed.
_HISTORICAL_MARKER_RE = re.compile(
    r"\b(?:"
    r"in\s+(?:late\s+|early\s+)?(?:january|february|march|april|may|june|"
    r"july|august|september|october|november|december)"
    r"|last\s+(?:year|month|quarter|week)"
    r"|previously"
    r"|earlier\s+this\s+(?:year|month)"
    r"|a\s+(?:prior|previous|separate)\s+(?:incident|breach|attack|compromise)"
    r"|the\s+previous\s+(?:attack|breach|incident)"
    r"|an?\s+earlier\s+(?:attack|breach|incident)"
    r")\b",
    flags=re.IGNORECASE,
)


GENERIC_ACTOR_NAMES = {
    "hackers",
    "attackers",
    "threat actors",
    "ransomware group",
    "ransomware gang",
    "cybercriminals",
    "criminal group",
    "unknown",
    "unknown actor",
    "unidentified",
    # "global" was an erroneous THREAT_ACTORS entry that matched company descriptions
    # like "global medical technology company" — treat as generic so events re-attribute.
    "global",
}


_CLAIMED_PATTERNS = [
    "claimed responsibility",
    "claims responsibility",
    "claiming responsibility",
    "claimed the attack",
    "claimed the breach",
    "claimed credit",
    "claims credit",
    "took credit",
    "claimed they",
    "claims they",
    "claimed to have",
    "claims to have",
    "claim to have",
    "claiming to have",
    "claimed to",
    "claimed it",
    "claimed that",
    "claiming that",
    "claimed by",
    "has claimed",
    "have claimed",
    "is claiming",
    "added the company to",
    "listed the victim on",
    "posted on its leak site",
    "posted on their leak site",
    "added to its leak site",
    "added to their leak site",
    "named on its leak site",
    "named on their leak site",
    "leaked data on its",
    "leaked data on their",
    "demonstrated they",
    "demonstrated access",
]
_CONFIRMED_PATTERNS = [
    "officials confirmed",
    "officials said",
    "fbi confirmed",
    "cisa confirmed",
    "investigators confirmed",
    "investigators determined",
    "researchers confirmed",
    "the company attributed",
    "the company attributed the attack",
    "victim confirmed",
    "decision to pay",
    "agreed to pay",
    "confirming their decision",
]
_SUSPECTED_PATTERNS = [
    "suspected",
    "linked to",
    "believed to be",
    "attributed to",
    "tied to",
    "associated with",
    "behind the attack",
    "behind the breach",
    "appears to be",
    "consistent with",
    "tactics overlap with",
]


def _is_generic_actor_name(name):
    if not name:
        return True
    return name.strip().lower() in GENERIC_ACTOR_NAMES


def _build_actor_pattern(name):
    """
    Compile a case-insensitive word-boundary regex for an actor name or alias.
    Special characters (e.g. $, /, parentheses, digits) are properly escaped.
    """
    escaped = re.escape(name)
    # Loose word-ish boundaries that work for tokens with $ and digits.
    return re.compile(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", flags=re.IGNORECASE)


_ACTOR_PATTERNS = []
for canonical, info in THREAT_ACTORS.items():
    actor_type = info["actor_type"]
    names = [canonical] + list(info.get("aliases") or [])
    for name in names:
        _ACTOR_PATTERNS.append((canonical, actor_type, name, _build_actor_pattern(name)))

# Sort patterns by name length descending so multi-word aliases match before
# their bare-name variants ("LockBit 3.0" before "LockBit").
_ACTOR_PATTERNS.sort(key=lambda row: len(row[2]), reverse=True)


def find_actor_in_text(text, victim_tokens=None):
    """
    Scan text for any known actor name or alias.

    Returns (canonical_name, actor_type, attribution_status, match_offset)
    or None.

    Guards (applied to every occurrence of the actor name via finditer):
    1. Attribution language must appear within 200 chars of the actor name.
       Pure mentions ("similar to X tactics", news analysis) are ignored.
    2. If victim_tokens is provided, at least one victim token must appear in
       the same 400-char window. This ties the attribution to the current
       event's subject and prevents false positives from actor mentions that
       describe attacks on different victims in the same article.
    3. Historical temporal marker in the 50 chars immediately before the actor
       name suppresses that occurrence (not the full 200-char window, so that
       "last year" in a prior sentence does not block a current attribution).

    Using finditer means every occurrence is checked: if the first mention is
    in a historical sentence the next occurrence can still match.
    """
    if not text:
        return None

    all_attribution = _CLAIMED_PATTERNS + _CONFIRMED_PATTERNS + _SUSPECTED_PATTERNS

    best = None
    for canonical, actor_type, _name, pattern in _ACTOR_PATTERNS:
        for match in pattern.finditer(text):
            offset = match.start()
            window_start = max(0, offset - 200)
            window_end = min(len(text), offset + 200)
            window = text[window_start:window_end].lower()

            # Guard 1: attribution language required near the actor name
            if not any(phrase in window for phrase in all_attribution):
                continue

            # Guard 1.5: short single-word aliases must appear adjacent to
            # explicit actor-class language to prevent brand-name collisions
            # (e.g. "Play" matching "Google Play Store").  A tight ±30-char
            # window ensures "Play ransomware" or "Play gang" match, but
            # "Google Play Store / Protect" do not, even when the article body
            # discusses threat actors elsewhere in the same paragraph.
            if _alias_requires_actor_context(_name):
                actor_window = text[max(0, offset - 30):min(len(text), offset + 30)]
                if not _ACTOR_CLASS_CONTEXT_RE.search(actor_window):
                    continue

            # Guard 2: victim proximity — prevent attributions that are about a
            # different victim mentioned in the same article.
            # Single-token victims (e.g. "NVIDIA") only need to appear anywhere
            # in the full text — the article body often uses a product name
            # ("GeForce NOW") rather than the company name near the attribution.
            # Multi-token victims require at least one significant token in the
            # local window, which disambiguates e.g. "South Staffordshire Water"
            # from "Thames Water" when Cl0p claims one in an article about the other.
            if victim_tokens:
                if len(victim_tokens) == 1:
                    if not victim_tokens.intersection(
                        set(re.findall(r"\w+", text.lower()))
                    ):
                        continue
                else:
                    if not victim_tokens.intersection(
                        set(re.findall(r"\w+", window))
                    ):
                        continue

            # Guard 3: historical temporal marker in the 50 chars immediately
            # before the actor name suppresses this occurrence only
            pre_actor = text[max(0, offset - 50):offset]
            if _HISTORICAL_MARKER_RE.search(pre_actor):
                continue

            if best is None or offset < best[3]:
                status = _classify_attribution_status(text, offset)
                best = (canonical, actor_type, status, offset)
            break  # found a valid occurrence for this actor; move to next actor

    return best


def _classify_attribution_status(text, offset):
    window_start = max(0, offset - 160)
    window_end = min(len(text), offset + 160)
    window = text[window_start:window_end].lower()

    if any(phrase in window for phrase in _CLAIMED_PATTERNS):
        return "claimed"
    if any(phrase in window for phrase in _CONFIRMED_PATTERNS):
        return "confirmed"
    if any(phrase in window for phrase in _SUSPECTED_PATTERNS):
        return "suspected"
    return "suspected"


def _event_articles_text(event):
    links = (
        EventSourceLink.query
        .filter_by(cyber_event_id=event.id)
        .order_by(EventSourceLink.linked_at.desc())
        .all()
    )

    parts = []
    for link in links:
        article = RawArticle.query.get(link.raw_article_id)
        if not article:
            continue
        parts.extend([
            article.title or "",
            article.summary or "",
            article.content or "",
        ])
    return " ".join(parts)


def _is_eligible_for_attribution(event):
    if event.event_signal_type not in ("incident",):
        return False
    if not event.victim_org_name:
        return False
    if event.actor_name and not _is_generic_actor_name(event.actor_name):
        return False
    return True


def attribute_event(event):
    """
    Run actor recognition on a single event. Returns True if any actor
    field changed.
    """
    if not _is_eligible_for_attribution(event):
        return False

    text = _event_articles_text(event)
    victim_tokens = (
        set(re.findall(r"\w+", event.victim_org_name.lower()))
        if event.victim_org_name
        else None
    )
    match = find_actor_in_text(text, victim_tokens=victim_tokens)
    if not match:
        return False

    canonical, actor_type, status, _offset = match
    changed = False
    if event.actor_name != canonical:
        event.actor_name = canonical
        changed = True
    if event.actor_type != actor_type:
        event.actor_type = actor_type
        changed = True
    if event.attribution_status != status:
        event.attribution_status = status
        changed = True
    return changed


def attribute_events():
    """
    Public entry point. Iterate every event and apply deterministic actor
    recognition where eligible. Returns a stats dict.
    """
    summary = {
        "events_considered": 0,
        "events_changed": 0,
    }

    events = CyberEvent.query.all()
    for event in events:
        if not _is_eligible_for_attribution(event):
            continue
        summary["events_considered"] += 1
        if attribute_event(event):
            summary["events_changed"] += 1
            event.last_enriched_at = datetime.utcnow()

    # Pass 2: supply-chain / campaign incidents with no named org victim.
    # The normal eligibility check blocks these because no victim → no actor,
    # but when the article explicitly names a known actor with attribution
    # language, propagate it directly.
    no_victim_incidents = CyberEvent.query.filter(
        CyberEvent.event_signal_type == "incident",
        CyberEvent.victim_org_name.is_(None),
        CyberEvent.actor_name.is_(None),
    ).all()
    for event in no_victim_incidents:
        text = _event_articles_text(event)
        result = find_actor_in_text(text)
        if result:
            canonical, actor_type, status, _ = result
            event.actor_name = canonical
            event.actor_type = actor_type
            event.attribution_status = status
            event.last_enriched_at = datetime.utcnow()
            summary["events_changed"] += 1

    db.session.commit()

    high_impact_updated = recompute_high_impact()
    summary["high_impact_recomputed"] = high_impact_updated

    return summary
