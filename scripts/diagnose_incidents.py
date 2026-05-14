"""
Audit all incident events. Shows each event in a compact format with
quality flags so gaps are immediately visible.

Flags:
  [NO ACTOR]      victim is set but no actor attributed
  [NO VICTIM]     no victim and no actor (should be excluded by feed floor)
  [UNKNOWN TYPE]  attack_type is Unknown
  [UNKNOWN IND]   industry is Unknown
  [NO GEO]        no country and no region
  [LOW SCORE]     confidence_score < 50
"""
from app import create_app
from app.models import CyberEvent, EventSourceLink, RawArticle

app = create_app()
with app.app_context():
    events = (
        CyberEvent.query
        .filter(CyberEvent.event_signal_type == "incident")
        .order_by(CyberEvent.confidence_score.desc().nullslast())
        .all()
    )

    print(f"{'='*80}")
    print(f"INCIDENT EVENTS — {len(events)} total")
    print(f"{'='*80}\n")

    issues = []

    for i, e in enumerate(events, 1):
        flags = []
        if not e.actor_name and e.victim_org_name:
            flags.append("NO ACTOR")
        if not e.victim_org_name and not e.actor_name:
            flags.append("NO VICTIM")
        if not e.attack_type or e.attack_type == "Unknown":
            flags.append("UNKNOWN TYPE")
        if not e.industry or e.industry == "Unknown":
            flags.append("UNKNOWN IND")
        if not e.country and not e.region:
            flags.append("NO GEO")
        if e.confidence_score is not None and e.confidence_score < 50:
            flags.append("LOW SCORE")

        flag_str = f"  !! {', '.join(flags)}" if flags else ""

        # Source names
        links = EventSourceLink.query.filter_by(cyber_event_id=e.id).all()
        source_names = []
        for lnk in links:
            a = RawArticle.query.get(lnk.raw_article_id)
            if a:
                source_names.append(a.source_name)
        sources = ", ".join(sorted(set(source_names))) or "—"

        score = f"{e.confidence_score:.0f}" if e.confidence_score is not None else "—"
        geo = " / ".join(filter(None, [e.country, e.region])) or "—"

        print(f"[{i:02d}] {e.victim_org_name or '(no victim)'}")
        print(f"     Type: {e.attack_type or '—':<22}  Score: {score:<6}  Impact: {'Yes' if e.is_high_impact else 'No'}")
        print(f"     Actor: {e.actor_name or '—'}")
        print(f"     Geo: {geo:<30}  Industry: {e.industry or '—'}")
        print(f"     Sources: {sources}")
        if e.summary_short:
            print(f"     Summary: {e.summary_short[:120]}")
        if flags:
            print(f"     !! {', '.join(flags)}")
        print()

        if flags:
            issues.append((i, e.victim_org_name or "(no victim)", flags))

    print(f"{'='*80}")
    print(f"QUALITY SUMMARY")
    print(f"{'='*80}")
    if issues:
        for idx, victim, flags in issues:
            print(f"  [{idx:02d}] {victim:<35} {', '.join(flags)}")
    else:
        print("  All events look clean.")
    print()
