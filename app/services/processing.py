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
    """
    text = _combined_article_text(article)

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
        "adds",
        "introduces",
        "launches",
        "announces",
        "upcoming webinar",
        "join our upcoming webinar",
        "learn how to",
        "how to",
        "guide",
        "opinion",
        "tips",
        "best practices",
        "security goalposts",
        "accuses",
        "accused of",
        "charged with",
        "indicted",
        "arrested",
        "sentenced",
        "pleaded guilty",
        "pleads guilty",
        "extradited",
        "former journalist",
        "state-owned media",
    ]

    strong_incident_phrases = [
        "hit by ransomware",
        "ransomware attack",
        "phishing attack",
        "data breach",
        "security breach",
        "cyberattack",
        "cyber attack",
        "actively exploited",
        "under active exploitation",
        "forced offline",
        "taken offline",
        "service disruption",
        "operational disruption",
        "targeted in attacks",
        "under attack",
        "compromised",
        "breached",
        "hacked",
        "malware campaign",
        "phishing campaign",
        "ddos attack",
        "denial-of-service attack",
        "credential theft",
        "stolen credentials",
        "data leak",
        "intrusion",
        "backdoor",
        "extortion",
        "victims of",
        "victim of",
        "exposed to cyberattacks",
    ]

    incident_entities = [
        "hospital",
        "healthcare",
        "provider",
        "school",
        "university",
        "government",
        "agency",
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
    ]

    if any(keyword in text for keyword in negative_keywords):
        return False

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
            "exploit",
            "exploitation",
            "botnet",
            "ddos",
            "compromised",
            "breached",
            "hacked",
            "intrusion",
            "stolen credentials",
            "data leak",
        ]
    )

    has_victim_context = any(entity in text for entity in incident_entities)

    return has_attack_word and has_victim_context

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