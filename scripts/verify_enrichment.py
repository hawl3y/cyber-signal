"""
Read-only diagnostic for the event-level enrichment stage. Prints totals,
field-coverage counts, data-integrity rule check, and any recorded failures.
Safe to run any time from the Render shell: python scripts/verify_enrichment.py
"""
from app import create_app
from app.models import CyberEvent
from app.services.event_enrichment import _has_fillable_blanks


def _filled(event, field):
    value = getattr(event, field)
    return bool(value) and str(value).lower() != "unknown"


app = create_app()

with app.app_context():
    events = CyberEvent.query.all()
    total = len(events)
    incidents = sum(1 for e in events if e.event_signal_type == "incident")
    activity = sum(1 for e in events if e.event_signal_type == "activity")
    enriched = sum(1 for e in events if e.last_enriched_at)
    blanks_left = sum(1 for e in events if _has_fillable_blanks(e))
    failures = [e for e in events if e.ai_event_error]

    print("== events ==")
    print(f"  total:                  {total}")
    print(f"    incidents:            {incidents}")
    print(f"    activity:             {activity}")
    print(f"  enriched (timestamp):   {enriched}")
    print(f"  fillable blanks left:   {blanks_left}")
    print(f"  ai_event_error set:     {len(failures)}")

    print()
    print("== field coverage (filled / total) ==")
    for field in (
        "industry",
        "attack_type",
        "country",
        "region",
        "victim_org_name",
        "actor_name",
        "summary_short",
    ):
        count = sum(1 for e in events if _filled(e, field))
        print(f"  {field:<22} {count}/{total}")

    print()
    print("== integrity check ==")
    violations = []
    for e in events:
        if e.event_signal_type == "activity" and (
            e.victim_org_name or e.actor_name or e.attribution_status
        ):
            violations.append(f"  id={e.id}: activity has victim/actor/attribution")
        if not e.victim_org_name and (e.actor_name or e.attribution_status):
            violations.append(f"  id={e.id}: no victim but actor/attribution set")
        if not e.actor_name and (e.actor_type or e.attribution_status):
            violations.append(f"  id={e.id}: no actor but actor_type/attribution set")
    if violations:
        for v in violations:
            print(v)
    else:
        print("  all rules pass")

    if failures:
        print()
        print("== first 5 failures ==")
        for e in failures[:5]:
            err = (e.ai_event_error or "")[:200]
            print(f"  id={e.id} sig={e.event_signal_type}: {err}")

    blanks = [e for e in events if _has_fillable_blanks(e)][:5]
    if blanks:
        print()
        print("== first 5 events with remaining blanks ==")
        for e in blanks:
            print(
                f"  id={e.id} sig={e.event_signal_type:<8} "
                f"ind={(e.industry or '-'):<18} "
                f"attack={(e.attack_type or '-'):<15} "
                f"country={(e.country or '-'):<14} "
                f"actor={(e.actor_name or '-')}"
            )
