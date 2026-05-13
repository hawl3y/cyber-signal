"""
Diagnose events with missing actors — shows what attribution found and why
find_actor_in_text returned None (which guard blocked it, what text was seen).
"""
import re
from app import create_app
from app.models import CyberEvent, EventSourceLink, ArticleExtraction
from app.services.actor_recognition import (
    find_actor_in_text,
    _event_articles_text,
    _ACTOR_PATTERNS,
    _HISTORICAL_MARKER_RE,
)
from app.services.actor_recognition import (
    _CLAIMED_PATTERNS,
    _CONFIRMED_PATTERNS,
    _SUSPECTED_PATTERNS,
)

app = create_app()
with app.app_context():
    ALL_ATTRIBUTION = _CLAIMED_PATTERNS + _CONFIRMED_PATTERNS + _SUSPECTED_PATTERNS

    events = (
        CyberEvent.query
        .filter(
            CyberEvent.event_signal_type == "incident",
            CyberEvent.victim_org_name.isnot(None),
            CyberEvent.actor_name.is_(None),
        )
        .order_by(CyberEvent.confidence_score.desc())
        .limit(20)
        .all()
    )

    print(f"=== {len(events)} INCIDENT EVENTS WITH VICTIM BUT NO ACTOR ===\n")

    for event in events:
        print(f"id={event.id} score={event.confidence_score} victim={event.victim_org_name!r}")
        print(f"  {event.canonical_title[:90]!r}")

        combined = _event_articles_text(event)

        result = find_actor_in_text(combined)
        if result:
            print(f"  FOUND: actor={result[0]!r} status={result[2]!r}")
            print()
            continue

        # Drill into why each known actor pattern missed
        blocked = []
        for canonical, actor_type, name, pattern in _ACTOR_PATTERNS:
            match = pattern.search(combined)
            if not match:
                continue
            offset = match.start()
            window_start = max(0, offset - 200)
            window_end = min(len(combined), offset + 200)
            window = combined[window_start:window_end].lower()
            pre_actor = combined[window_start:offset]

            matched_phrase = next(
                (p for p in ALL_ATTRIBUTION if p in window), None
            )
            historical = _HISTORICAL_MARKER_RE.search(pre_actor)

            if not matched_phrase:
                blocked.append(
                    f"  BLOCKED (no attribution phrase) [{canonical}] "
                    f"window: ...{combined[max(0,offset-60):offset+80]!r}..."
                )
            elif historical:
                blocked.append(
                    f"  BLOCKED (historical marker) [{canonical}] "
                    f"marker={historical.group()!r} "
                    f"window: ...{combined[max(0,offset-60):offset+80]!r}..."
                )
            else:
                blocked.append(
                    f"  PASSED guards but not best [{canonical}] phrase={matched_phrase!r}"
                )

        if blocked:
            for b in blocked[:5]:
                print(b)
        else:
            print("  No known actor names found in article text at all")

        print()
