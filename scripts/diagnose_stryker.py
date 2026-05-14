"""
Diagnose the Stryker event: show current event state, what extraction
produces now, and what text is triggering the wrong attack type.
"""
from app import create_app
from app.models import CyberEvent, RawArticle, EventSourceLink
from app.services.extraction import run_rule_extraction

app = create_app()
with app.app_context():
    event = CyberEvent.query.filter(
        CyberEvent.victim_org_name.ilike("%stryker%")
    ).first()

    if not event:
        print("Stryker event not found")
        exit()

    print(f"=== Event ===")
    print(f"  victim:      {event.victim_org_name}")
    print(f"  attack_type: {event.attack_type}")
    print(f"  actor_name:  {event.actor_name}")
    print(f"  country:     {event.country}")
    print(f"  region:      {event.region}")
    print(f"  signal_type: {event.event_signal_type}")
    print()

    links = EventSourceLink.query.filter_by(cyber_event_id=event.id).all()
    for link in links:
        article = RawArticle.query.get(link.raw_article_id)
        if not article:
            continue
        print(f"=== Article: {article.source_name} ===")
        print(f"  status: {article.processing_status}")
        print(f"  title:  {article.title}")
        print()

        signals = run_rule_extraction(article)
        print(f"=== Extraction output ===")
        print(f"  victim:      {signals.get('victim_org_name')}")
        print(f"  attack_type: {signals.get('attack_type')}")
        print(f"  actor_name:  {signals.get('actor_name')}")
        print(f"  country:     {signals.get('country')}")
        print(f"  region:      {signals.get('region')}")
        print()

        # Show which supply chain phrases appear in article text
        text = " ".join([
            (article.title or ""),
            (article.summary or ""),
            (article.content or ""),
        ]).lower()

        sc_phrases = [
            "supply chain attack", "supply chain compromise", "supply chain hack",
            "supply chain intrusion", "supply-chain attack", "supply chain infection",
            "attacked via supply chain", "malicious package", "malicious update",
            "poisoned package", "dependency confusion", "compromised vendor",
            "third-party compromise", "software supply chain",
        ]
        print("Supply chain phrase hits in article text:")
        for phrase in sc_phrases:
            if phrase in text:
                idx = text.index(phrase)
                print(f"  MATCH '{phrase}': ...{text[max(0,idx-60):idx+80]}...")
        print()

        print(f"Actor mentions (first 3000 chars of content):")
        content_sample = (article.content or "")[:3000]
        for line in content_sample.split("\n"):
            if any(w in line.lower() for w in ["iran", "claim", "responsible", "hacktivist", "sparrow", "gonjeshke", "wiper", "actor", "group"]):
                print(f"  {line.strip()}")
