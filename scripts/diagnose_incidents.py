"""
Audit all incident events. Shows feed events (named victim) first,
then a summary of what's excluded from the feed and why.

Flags on feed events:
  [NO ACTOR]      victim is set but no actor attributed
  [UNKNOWN TYPE]  attack_type is Unknown
  [UNKNOWN IND]   industry is Unknown
  [NO GEO]        no country and no region
  [LOW SCORE]     confidence_score < 50
"""
from app import create_app
from app.models import CyberEvent, EventSourceLink, RawArticle

app = create_app()
with app.app_context():
    all_incidents = (
        CyberEvent.query
        .filter(CyberEvent.event_signal_type == "incident")
        .order_by(CyberEvent.confidence_score.desc().nullslast())
        .all()
    )

    in_feed = [e for e in all_incidents if e.victim_org_name]
    excluded = [e for e in all_incidents if not e.victim_org_name]

    def source_names(event):
        links = EventSourceLink.query.filter_by(cyber_event_id=event.id).all()
        names = set()
        for lnk in links:
            a = RawArticle.query.get(lnk.raw_article_id)
            if a:
                names.add(a.source_name)
        return ", ".join(sorted(names)) or "—"

    issues = []

    print(f"{'='*80}")
    print(f"IN FEED — {len(in_feed)} named-victim incident events")
    print(f"{'='*80}\n")

    for i, e in enumerate(in_feed, 1):
        flags = []
        if not e.actor_name:
            flags.append("NO ACTOR")
        if not e.attack_type or e.attack_type == "Unknown":
            flags.append("UNKNOWN TYPE")
        if not e.industry or e.industry == "Unknown":
            flags.append("UNKNOWN IND")
        if not e.country and not e.region:
            flags.append("NO GEO")
        if e.confidence_score is not None and e.confidence_score < 50:
            flags.append("LOW SCORE")

        score = f"{e.confidence_score:.0f}" if e.confidence_score is not None else "—"
        geo = " / ".join(filter(None, [e.country, e.region])) or "—"

        print(f"[{i:02d}] {e.victim_org_name}")
        print(f"     Type: {e.attack_type or '—':<22}  Score: {score:<6}  Impact: {'Yes' if e.is_high_impact else 'No'}")
        print(f"     Actor: {e.actor_name or '—'}")
        print(f"     Geo: {geo:<30}  Industry: {e.industry or '—'}")
        print(f"     Sources: {source_names(e)}")
        if e.summary_short:
            print(f"     Summary: {e.summary_short[:120]}")
        if flags:
            print(f"     !! {', '.join(flags)}")
        print()

        if flags:
            issues.append((i, e.victim_org_name, flags))

    print(f"{'='*80}")
    print(f"EXCLUDED FROM FEED — {len(excluded)} events (no named victim)")
    print(f"{'='*80}\n")

    for e in excluded:
        score = f"{e.confidence_score:.0f}" if e.confidence_score is not None else "—"
        actor = e.actor_name or "—"
        summary = (e.summary_short or "")[:80]
        print(f"  {e.attack_type or 'Unknown':<22}  score={score:<4}  actor={actor:<20}  {source_names(e)}")
        print(f"  {summary}")
        print()

    print(f"{'='*80}")
    print(f"FEED QUALITY SUMMARY — {len(issues)} events with flags")
    print(f"{'='*80}")
    if issues:
        for idx, victim, flags in issues:
            print(f"  [{idx:02d}] {victim:<40} {', '.join(flags)}")
    else:
        print("  All feed events look clean.")
    print()
