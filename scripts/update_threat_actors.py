"""
Fetch threat actor data from MITRE ATT&CK, compare against the current
THREAT_ACTORS knowledge base, and print a Python snippet of additions
ready to paste into app/data/threat_actors.py.

Usage:
    PYTHONPATH=. python scripts/update_threat_actors.py

Run this periodically after major ATT&CK updates or new campaign reporting.
"""

import json
import re
import sys
import requests

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
    return re.sub(r"\s+", " ", (name or "").strip()).lower()


def _fetch_mitre_groups():
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
        groups.append((name, aliases, "nation_state"))

    print(f"  {len(groups)} MITRE groups loaded.", flush=True)
    return groups


def main():
    known = _load_current_actors()
    print(f"Current knowledge base: {len(known)} names/aliases\n")

    all_groups = _fetch_mitre_groups()

    new_entries = []
    seen_canonicals = set()

    for canonical, aliases, actor_type in all_groups:
        if _normalise(canonical) in known:
            continue
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
