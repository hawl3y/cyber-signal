"""
Fetch threat actor data from MITRE ATT&CK and ransomware.live, compare
against the current THREAT_ACTORS knowledge base, and print a Python
snippet of additions ready to paste into app/data/threat_actors.py.

Usage:
    PYTHONPATH=. python scripts/update_threat_actors.py

Sources:
  - MITRE ATT&CK enterprise groups (via attack-stix-data on GitHub)
  - ransomware.live /groups API

Run this periodically after major ransomware campaigns or ATT&CK updates.
"""

import json
import re
import sys
import requests

RANSOMWARE_LIVE_URL = "https://api.ransomware.live/groups"
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack-16.1.json"
)


def _load_current_actors():
    """Return the set of all canonical names and aliases already in THREAT_ACTORS."""
    sys.path.insert(0, ".")
    from app.data.threat_actors import THREAT_ACTORS

    known = set()
    for canonical, data in THREAT_ACTORS.items():
        known.add(canonical.lower())
        for alias in data.get("aliases", []):
            known.add(alias.lower())
    return known


def _normalise(name):
    """Lowercase, collapse whitespace for comparison."""
    return re.sub(r"\s+", " ", (name or "").strip()).lower()


def _fetch_mitre_groups():
    """
    Download the MITRE ATT&CK STIX bundle and return a list of
    (canonical_name, [aliases], actor_type) tuples.
    actor_type is nation_state for all MITRE groups (mix of state + criminal
    groups; the ones that are criminal are also in ransomware.live and will
    be tagged there).
    """
    print("Fetching MITRE ATT&CK STIX data (this may take a moment)...", flush=True)
    try:
        resp = requests.get(MITRE_STIX_URL, timeout=60, stream=True)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"  WARNING: could not fetch MITRE data — {exc}", file=sys.stderr)
        return []

    groups = []
    for obj in data.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        name = obj.get("name", "").strip()
        if not name:
            continue
        aliases = [a for a in obj.get("aliases", []) if a != name]
        # MITRE mixes nation-state and criminal groups — mark all as nation_state
        # here; ransomware.live will correctly tag the criminal ones.
        groups.append((name, aliases, "nation_state"))

    print(f"  {len(groups)} MITRE groups loaded.", flush=True)
    return groups


def _fetch_ransomware_live_groups():
    """
    Fetch ransomware.live /groups and return a list of
    (canonical_name, [aliases], actor_type) tuples.
    """
    print("Fetching ransomware.live groups...", flush=True)
    try:
        resp = requests.get(RANSOMWARE_LIVE_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"  WARNING: could not fetch ransomware.live groups — {exc}", file=sys.stderr)
        return []

    groups = []
    for entry in data:
        name = (entry.get("name") or "").strip()
        if not name:
            continue
        altname = (entry.get("altname") or "").strip()
        aliases = [a.strip() for a in altname.split(",") if a.strip() and a.strip() != name] if altname else []
        groups.append((name, aliases, "cybercriminal"))

    print(f"  {len(groups)} ransomware.live groups loaded.", flush=True)
    return groups


def main():
    known = _load_current_actors()
    print(f"Current knowledge base: {len(known)} names/aliases\n")

    mitre_groups = _fetch_mitre_groups()
    rl_groups = _fetch_ransomware_live_groups()

    # MITRE first, then ransomware.live. For duplicates (e.g. LockBit appears
    # in both), ransomware.live wins on actor_type (cybercriminal is more precise
    # for RaaS operators).
    all_groups = mitre_groups + rl_groups

    new_entries = []
    seen_canonicals = set()

    for canonical, aliases, actor_type in all_groups:
        if _normalise(canonical) in known:
            continue
        # Also skip if any alias already covers this group
        if any(_normalise(a) in known for a in aliases):
            continue
        key = _normalise(canonical)
        if key in seen_canonicals:
            continue
        seen_canonicals.add(key)
        new_entries.append((canonical, aliases, actor_type))

    if not new_entries:
        print("Knowledge base is already up to date — no additions needed.")
        return

    print(f"\n{len(new_entries)} new actors to add:\n")
    print("# ── paste into app/data/threat_actors.py ──────────────────────")
    for canonical, aliases, actor_type in sorted(new_entries, key=lambda x: x[0].lower()):
        alias_list = json.dumps(aliases)
        print(f'    "{canonical}": {{')
        print(f'        "aliases": {alias_list},')
        print(f'        "actor_type": "{actor_type}",')
        print(f'    }},')
    print("# ── end of additions ───────────────────────────────────────────")


if __name__ == "__main__":
    main()
