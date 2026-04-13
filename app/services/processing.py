from app.extensions import db
from app.models import RawArticle


def _combined_article_text(article):
    return " ".join(
        [
            (article.title or "").strip(),
            (article.summary or "").strip(),
            (article.content or "").strip(),
        ]
    ).lower()


def is_relevant_incident(article):
    """
    Return True only for articles that read like actual cyber incidents,
    active exploitation, breaches, or concrete victim/attack reporting.

    Goal:
    - keep real incident reporting
    - reduce advisory / webinar / conference / product / trend noise
    - push toward >=80% high-signal feed quality
    """
    text = _combined_article_text(article)
    title = (article.title or "").strip().lower()
    summary = (article.summary or "").strip().lower()

    negative_keywords = [
        "webinar",
        "podcast",
        "sponsored",
        "subscription",
        "pricing",
        "product update",
        "product launch",
        "feature release",
        "new feature",
        "available now",
        "now available",
        "rolls out",
        "rolled out",
        "introduces",
        "launches",
        "announces",
        "announcement",
        "upcoming webinar",
        "join our upcoming webinar",
        "learn how to",
        "how to",
        "guide",
        "opinion",
        "tips",
        "best practices",
        "patch tuesday",
        "security update",
        "software update",
        "firmware update",
        "update fixes",
        "release notes",
        "researchers found",
        "study shows",
        "report finds",
        "analysis of",
        "analysis reveals",
        "roundup",
        "review",
        "forecast",
        "prediction",
        "conference",
        "cyberuk",
        "annual review",
        "toolkit",
        "small businesses to receive",
        "statement following",
        "raises alert",
        "warns of",
        "warns",
        "advisory",
        "alert",
        "guidance",
        "recommendations",
        "mitigation",
        "new government cyber tool",
        "security boost",
        "blocked by new government cyber tool",
        "chatgpt rolls out",
        "google chrome adds",
    ]

    strong_incident_phrases = [
        "hit by ransomware",
        "ransomware attack",
        "phishing attack",
        "data breach",
        "security breach",
        "cyberattack",
        "cyber attack",
        "forced offline",
        "taken offline",
        "service disruption",
        "operational disruption",
        "under attack",
        "compromised",
        "breached",
        "hacked",
        "credential theft",
        "stolen credentials",
        "data leak",
        "unauthorized access",
        "customer data was accessed",
        "records were accessed",
        "systems were compromised",
        "network was compromised",
        "operations were disrupted",
        "disclosed a breach",
        "reported a breach",
        "confirmed a breach",
        "confirmed a cyberattack",
        "confirmed a ransomware attack",
        "downloaded personal data",
        "personal data belonging to members",
        "obtained control of credentials",
        "millions stolen in cyberattack",
    ]

    incident_entities = [
        "hospital",
        "healthcare",
        "provider",
        "school",
        "university",
        "government agency",
        "company",
        "vendor",
        "organization",
        "employees",
        "customers",
        "network",
        "infrastructure",
        "routers",
        "devices",
        "plc",
        "systems",
        "patients",
        "retailer",
        "bank",
        "manufacturer",
        "airline",
        "airport",
        "utility",
        "municipality",
        "county",
        "city",
        "gym chain",
        "chain",
    ]

    advisory_only_terms = [
        "advisory",
        "alert",
        "warning",
        "guidance",
        "mitigation",
        "recommendations",
        "tracked as cve",
        "cve-",
        "known exploited vulnerability",
        "known exploited vulnerabilities catalog",
        "kev catalog",
        "annual review",
        "conference",
        "toolkit",
        "news release",
    ]

    concrete_impact_terms = [
        "stolen",
        "disrupted",
        "offline",
        "breached",
        "compromised",
        "downloaded personal data",
        "customer data",
        "victims",
        "fraud victims",
        "affected members",
        "outage",
        "extortion",
    ]

    # Hard drop obvious noise first
    if any(keyword in text for keyword in negative_keywords):
        return False

    # Strong direct incident phrases
    if any(phrase in text for phrase in strong_incident_phrases):
        return True

    has_attack_word = any(
        word in text
        for word in [
            "ransomware",
            "phishing",
            "malware",
            "breach",
            "attack",
            "attacks",
            "attacker",
            "compromised",
            "breached",
            "hacked",
            "intrusion",
            "stolen credentials",
            "data leak",
            "unauthorized access",
            "extortion",
            "disruption",
            "outage",
            "fraud victims",
        ]
    )

    has_victim_context = any(entity in text for entity in incident_entities)
    has_concrete_impact = any(term in text for term in concrete_impact_terms)
    has_advisory_only_context = any(term in text for term in advisory_only_terms)

    # Keep concrete real-world incidents
    if has_attack_word and has_victim_context and has_concrete_impact:
        return True

    # Allow narrowly if title itself clearly reads like a real incident
    if (
        has_attack_word
        and has_victim_context
        and any(term in title for term in ["hack", "breach", "ransomware", "cyberattack", "stolen", "exposes"])
    ):
        return True

    # Drop advisory/trend content unless it has a clearly identified victim + impact
    if has_advisory_only_context:
        return False

    # Drop broad trend/statistics pieces
    if any(
        phrase in summary
        for phrase in [
            "threats facing",
            "continue to escalate",
            "targeting certain devices",
            "take immediate action",
            "helps organisations detect",
            "helps organizations detect",
            "reveals that",
            "raises alert",
        ]
    ):
        return False

    return False


def get_pending_articles():
    """
    Fetch articles waiting for processing.
    """
    return RawArticle.query.filter_by(processing_status="pending").all()


def is_duplicate(article):
    """
    Placeholder for duplicate detection logic.
    """
    return False


def mark_duplicate(article):
    """
    Mark an article as duplicate.
    """
    article.is_duplicate = True
    article.processing_status = "duplicate"
    db.session.commit()
    return article


def mark_irrelevant(article):
    """
    Mark an article as not relevant for incident extraction.
    """
    article.processing_status = "irrelevant"
    db.session.commit()
    return article


def clean_article(article):
    """
    Clean and normalize raw article text fields for downstream extraction.
    """
    cleaned_title = (article.title or "").strip()
    cleaned_summary = (article.summary or "").strip()
    cleaned_content = (article.content or "").strip()

    return {
        "title": cleaned_title,
        "normalized_title": cleaned_title.lower(),
        "summary": cleaned_summary,
        "content": cleaned_content,
        "is_relevant_incident": is_relevant_incident(article),
    }


def update_article(article, cleaned_data):
    """
    Apply cleaned data to an article.
    """
    article.title = cleaned_data.get("title", article.title)
    article.normalized_title = cleaned_data.get("normalized_title", article.normalized_title)
    article.summary = cleaned_data.get("summary", article.summary)
    article.content = cleaned_data.get("content", article.content)

    db.session.commit()
    return article


def mark_ready_for_extraction(article):
    """
    Mark article as ready for extraction.
    """
    article.processing_status = "ready_for_extraction"
    db.session.commit()
    return article