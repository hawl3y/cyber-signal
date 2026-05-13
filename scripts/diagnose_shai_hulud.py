"""
Inspect the Shai Hulud / TeamPCP supply-chain npm event in production.
Shows victim, geography, industry, actor, and extraction signals.
Run: PYTHONPATH=. python scripts/diagnose_shai_hulud.py
"""
from app import create_app
from app.models import CyberEvent, EventSourceLink, RawArticle
from app.services.extraction import run_rule_extraction
from app.services.actor_recognition import find_actor_in_text

app = create_app()
with app.app_context():
    # Find by title keywords
    articles = RawArticle.query.filter(
        RawArticle.title.ilike("%shai%") |
        RawArticle.title.ilike("%tanstack%") |
        RawArticle.title.ilike("%mistral%npm%")
    ).all()

    if not articles:
        print("No Shai Hulud article found.")
    else:
        for a in articles:
            print(f"\n=== ARTICLE [{a.source_name}] ===")
            print(f"title: {a.title}")
            print(f"status: {a.processing_status}")
            print(f"summary: {(a.summary or '')[:400]}")
            signals = run_rule_extraction(a)
            print(f"\nEXTRACTION:")
            print(f"  victim_org_name: {signals.get('victim_org_name')}")
            print(f"  victim_display_label: {signals.get('victim_display_label')}")
            print(f"  industry: {signals.get('industry')}")
            print(f"  attack_type: {signals.get('attack_type')}")
            print(f"  region: {signals.get('region')}")
            print(f"  country: {signals.get('country')}")
            text = " ".join([a.title or "", a.summary or "", a.content or ""])
            actor = find_actor_in_text(text)
            print(f"  actor: {actor[0] if actor else None}")

    # Also find the CyberEvent
    print("\n=== CYBER EVENTS ===")
    for ev in CyberEvent.query.filter(
        CyberEvent.victim_org_name.ilike("%npm%") |
        CyberEvent.victim_display_label.ilike("%npm%") |
        CyberEvent.summary_short.ilike("%tanstack%") |
        CyberEvent.summary_short.ilike("%shai%")
    ).all():
        print(f"id={ev.id} victim={ev.victim_org_name} display={ev.victim_display_label}")
        print(f"  attack={ev.attack_type} industry={ev.industry} region={ev.region} actor={ev.actor_name}")
