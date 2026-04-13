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
    title_and_summary = " ".join([title, summary]).strip()

    negative_title_patterns = [
        "webinar",
        "podcast",
        "sponsored",
        "subscription",
        "pricing",
        "rolls out",
        "rolled out",
        "introduces",
        "launches",
        "announces",
        "announcement",
        "initiative",
        "threat sharing",
        "end-to-end encryption",
        "adds infostealer protection",
        "protection against",
        "designed to block",
        "available now",
        "now available",
        "feature release",
        "product update",
        "product launch",
        "security update",
        "software update",
        "firmware update",
        "guide",
        "best practices",
        "tips",
        "review",
        "forecast",
        "prediction",
        "analysis of",
        "analysis reveals",
        "report finds",
        "study shows",
        "conference",
        "annual review",
        "toolkit",
        "advisory",
        "alert",
        "guidance",
        "recommendations",
        "mitigation",
        "international crackdown",
        "victims identified",
        "news release",
        "statement",
        "take down",
        "takedown",
        "phishing tool",
    ]

    if any(pattern in title_and_summary for pattern in negative_title_patterns):
        return False

    early_exclusion_phrases = [
        "targeting credentials",
        "targeting c-suite executives",
        "targeting executives",
        "senior executives' microsoft logins",
        "industrial devices exposed",
        "attack surface targeted",
        "internet-exposed programmable logic controllers",
        "widely used phishing tool",
        "phishing tool",
        "take down",
        "takedown",
    ]

    if any(phrase in text for phrase in early_exclusion_phrases):
        return False

    strong_incident_phrases = [
        "hit by ransomware",
        "ransomware attack",
        "phishing attack",
        "data breach",
        "security breach",
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
        "serve malicious executables",
        "download links on the official website to serve malicious",
        "gained access to an api",
        "threatening to release stolen data",
    ]

    if any(phrase in text for phrase in strong_incident_phrases):
        return True

    abstract_attack_only_phrases = [
        "targeting credentials",
        "targeting c-suite executives",
        "targeting executives",
        "targeting certain devices",
        "helps organisations detect",
        "helps organizations detect",
        "take immediate action",
        "threats facing",
        "continue to escalate",
        "latest annual review reveals",
        "phishing-as-a-service platform",
        "wearable biometric authentication",
        "blocking phishing relays",
        "not the session",
        "senior executives' microsoft logins",
        "industrial devices exposed",
        "attack surface targeted",
        "internet-exposed programmable logic controllers",
        "fake websites that looked like legitimate login portals",
        "widely used phishing tool",
    ]

    if any(phrase in text for phrase in abstract_attack_only_phrases):
        return False

    attack_terms = [
        "ransomware",
        "phishing",
        "malware",
        "breach",
        "attack",
        "attacks",
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
        "malicious executables",
        "backdoor",
        "infostealer",
    ]

    concrete_victim_terms = [
        "hospital",
        "healthcare provider",
        "software provider",
        "software vendor",
        "company",
        "vendor",
        "organization",
        "customers",
        "patients",
        "members",
        "bank",
        "manufacturer",
        "utility",
        "municipality",
        "county",
        "city",
        "gym chain",
        "website",
        "official website",
        "downloads",
        "api",
        "systems",
        "network",
    ]

    concrete_impact_terms = [
        "stolen",
        "disrupted",
        "offline",
        "breached",
        "compromised",
        "downloaded personal data",
        "customer data",
        "affected members",
        "outage",
        "extortion",
        "malicious executables",
        "serve malicious",
        "gained access",
        "forced offline",
        "taken offline",
        "release stolen data",
    ]

    advisory_only_terms = [
        "advisory",
        "alert",
        "warning",
        "guidance",
        "mitigation",
        "recommendations",
        "cve-",
        "known exploited vulnerability",
        "kev catalog",
        "conference",
        "toolkit",
        "news release",
    ]

    concrete_named_org_signals = [
        "official website",
        "download links",
        "cloud analytics platform",
        "software provider",
        "software vendor",
        "gym chain",
        "members",
        "customers",
        "patients",
        "api for the",
    ]

    exposure_only_phrases = [
        "devices exposed",
        "industrial devices exposed",
        "internet-exposed",
        "attack surface",
        "targeted by iranian-linked hackers",
    ]

    tool_or_service_reporting_phrases = [
        "phishing tool",
        "phishing-as-a-service",
        "widely used phishing tool",
        "create fake websites",
        "login portals for just $500",
        "was disrupted by the fbi",
        "law enforcement agencies",
    ]

    has_attack = any(term in text for term in attack_terms)
    has_concrete_victim = any(term in text for term in concrete_victim_terms)
    has_concrete_impact = any(term in text for term in concrete_impact_terms)
    has_advisory_only_context = any(term in text for term in advisory_only_terms)
    has_named_org_signal = any(term in text for term in concrete_named_org_signals)
    has_exposure_only = any(term in text for term in exposure_only_phrases)
    has_tool_or_service_reporting = any(term in text for term in tool_or_service_reporting_phrases)

    if has_advisory_only_context and not has_concrete_impact:
        return False

    if has_exposure_only and not has_named_org_signal:
        return False

    if has_tool_or_service_reporting and not has_named_org_signal:
        return False

    if "phishing" in text and "targeting" in text and not has_named_org_signal:
        return False

    if has_attack and has_concrete_victim and has_concrete_impact:
        return True

    if (
        has_attack
        and has_concrete_impact
        and has_named_org_signal
        and any(term in title for term in ["hack", "breach", "ransomware", "malware", "exposes"])
        and not any(term in title for term in ["analysis", "review", "statement", "warns", "announces"])
    ):
        return True

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