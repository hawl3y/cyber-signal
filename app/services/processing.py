from app.extensions import db
from app.models import RawArticle
from app.services.extraction import _extract_victim_org_name, _has_exploitation_signal


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
    Return True only for concrete cyber incidents involving a real victim,
    a completed compromise/disruption/breach, or active exploitation with
    specific malicious impact.

    This intentionally rejects:
    - product/security feature releases
    - advisories, research, analysis, webinars
    - law enforcement takedowns
    - campaign / targeting / exposure-only reporting
    - patch / fix / update reporting without concrete victim impact
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
        "announcement",
        "initiative",
        "feature release",
        "product update",
        "product launch",
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
        "news release",
        "take down",
        "takedown",
        "developer arrest",
        "arrest",
        "seizure",
        "law enforcement",
        "emergency fix",
        "fix for",
        "security update",
        "software update",
        "firmware update",
        "patch",
        "patches",
        "zero-day flaw",
        "flaw in",
        "vulnerability in",
        "cve-",
        "available now",
        "now available",
        "end-to-end encryption",
        "adds infostealer protection",
        "protection against",
        "designed to block",
    ]

    if any(pattern in title for pattern in negative_title_patterns):
        return False

    negative_context_phrases = [
        "targeting credentials",
        "targeting c-suite executives",
        "targeting executives",
        "targeted attacks on ngos",
        "non-governmental organizations and universities",
        "industrial devices exposed",
        "devices exposed",
        "internet-exposed",
        "attack surface",
        "attack surface targeted",
        "widely used phishing tool",
        "phishing tool",
        "phishing-as-a-service",
        "create fake websites",
        "login portals for just $500",
        "was disrupted by the fbi",
        "law enforcement agencies",
        "released an emergency security update",
        "security update for",
        "block info-stealing malware",
        "helps organisations detect",
        "helps organizations detect",
        "take immediate action",
        "threats facing",
        "continue to escalate",
        "latest annual review reveals",
        "analysis of 1 billion",
        "analysis of one billion",
        "human-scale security",
    ]

    if any(phrase in text for phrase in negative_context_phrases):
        return False

    strong_incident_phrases = [
        "hit by ransomware",
        "ransomware attack on",
        "data breach",
        "security breach",
        "breach of",
        "hack at",
        "hack of",
        "forced offline",
        "taken offline",
        "service disruption",
        "operational disruption",
        "systems were compromised",
        "network was compromised",
        "unauthorized access",
        "customer data was accessed",
        "records were accessed",
        "downloaded personal data",
        "gained access to an api",
        "serve malicious executables",
        "download links on the official website to serve malicious",
        "threatening to release stolen data",
        "ransom is not paid",
        "data leaked",
        "stolen data",
        "has suffered a data breach",
        "hackers breached its systems",
        "breached its systems",
        "confirmed a breach",
        "confirmed a cyberattack",
        "confirmed a ransomware attack",
        "reported a breach",
        "disclosed a breach",
        "insider breach",
        "extorted by hackers",
        "following extortion threat",
        "stole $",
        "stole £",
        "stole €",
        "theft from ",
    ]

    victim_org_name = _extract_victim_org_name(article)
    has_exploitation_subject = _has_exploitation_signal(text)

    if any(phrase in text for phrase in strong_incident_phrases):
        if victim_org_name or has_exploitation_subject:
            return True
        return False

    completed_incident_verbs = [
        "breached",
        "hacked",
        "compromised",
        "hit by ransomware",
        "suffered a data breach",
        "suffered a cyberattack",
        "was attacked",
        "was breached",
        "was hacked",
        "was compromised",
        "forced offline",
        "taken offline",
        "disrupted",
        "data leaked",
        "stolen data",
        "downloaded personal data",
        "gained access",
        "malicious executables",
        "extorted",
        "stole $",
        "stole £",
        "stole €",
        "theft from ",
    ]

    concrete_impact_terms = [
        "data breach",
        "security breach",
        "unauthorized access",
        "data leaked",
        "stolen data",
        "customer data",
        "personal data",
        "records were accessed",
        "downloaded personal data",
        "service disruption",
        "operational disruption",
        "forced offline",
        "taken offline",
        "extortion",
        "ransom",
        "malicious executables",
        "gained access to an api",
        "stole $",
        "stole £",
        "stole €",
        "theft",
    ]

    generic_only_victim_terms = [
        "customers",
        "customer",
        "patients",
        "members",
        "employees",
        "executives",
        "ngos",
        "universities",
        "organizations",
        "organisations",
        "victims",
        "users",
        "devices",
    ]

    concrete_org_context_terms = [
        "company",
        "software provider",
        "software vendor",
        "official website",
        "website",
        "api",
        "cloud analytics platform",
        "gym chain",
        "hospital",
        "healthcare provider",
        "vendor",
        "provider",
        "developer",
        "bank",
        "manufacturer",
        "utility",
        "municipality",
        "city of",
        "county",
    ]

    abstract_only_patterns = [
        "targeting",
        "used in attacks",
        "used in targeted attacks",
        "campaign targeting",
        "under active exploitation",
        "actively exploited",
        "known exploited vulnerability",
        "zero-day",
        "flaw",
        "vulnerability",
        "cve-",
        "phishing service",
        "phishing platform",
        "tool",
        "researchers",
        "report",
        "analysis",
        "study",
    ]

    has_completed_incident = any(term in text for term in completed_incident_verbs)
    has_concrete_impact = any(term in text for term in concrete_impact_terms)
    has_generic_only_victim = any(term in text for term in generic_only_victim_terms)
    has_concrete_org_context = any(term in text for term in concrete_org_context_terms)
    has_abstract_only = any(term in text for term in abstract_only_patterns)

    if has_abstract_only and not has_completed_incident and not has_concrete_impact:
        return False

    if "targeting" in text and not has_completed_incident and not has_concrete_impact:
        return False

    if "exposed" in text and not has_completed_incident and not has_concrete_impact:
        return False

    if "under active exploitation" in text and not any(
        term in text for term in [
            "credential theft",
            "stolen credentials",
            "data theft",
            "malware",
            "backdoor",
            "ransomware",
        ]
    ):
        return False

    if has_completed_incident and (has_concrete_impact or has_concrete_org_context):
        if victim_org_name or has_exploitation_subject:
            return True
        return False

    if has_concrete_impact and has_concrete_org_context:
        if victim_org_name or has_exploitation_subject:
            return True
        return False

    if has_concrete_impact and has_generic_only_victim and has_completed_incident:
        if victim_org_name:
            return True
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