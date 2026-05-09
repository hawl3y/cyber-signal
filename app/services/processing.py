import re

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
    Return True for concrete cyber incident reporting.

    Admit:
    - named-victim incidents
    - exploitation with concrete malicious outcome
    - attack/campaign reports with a direct attacked target class

    Reject:
    - product/advisory/research/takedown reporting
    - trend/analysis/reporting articles about cyber activity
    - articles without a concrete attack construction
    """
    text = _combined_article_text(article)
    title = (article.title or "").strip().lower()
    summary = (article.summary or "").strip().lower()
    title_and_summary = " ".join([title, summary]).strip()

    if article.source_name == "cisa-alerts-advisories":
        advisory_noise_patterns = [
            "cisa adds",
            "defending against",
            "zero trust",
            "agentic ai",
            "careful adoption",
            "recommended practices",
            "appendix:",
            "mitre att&ck",
            "version history",
            "legal notice and terms of use",
            "acknowledgments",
            "incident response",
            "protective advice",
            "all organizations",
            "u.s. fceb agencies",
            "uk organizations",
            "largest or most at-risk organizations",
            "cyber security best practices",
            "malware analysis report at a glance",
        ]

        if any(pattern in title_and_summary for pattern in advisory_noise_patterns):
            return False

        return True

    legal_followup_patterns = [
        "sentenced to",
        "sentenced for",
        "sentenced after",
        "pleaded guilty",
        "pleads guilty",
        "plead guilty",
        "convicted",
        "prison sentence",
        "gets 30 months",
        "gets 24 months",
        "gets 12 months",
        "jailed",
        "indicted",
        "charged with",
        "arrested",
        "arrest",
        "seized",
        "seizure",
        "takedown",
        "take down",
    ]

    if any(pattern in title_and_summary for pattern in legal_followup_patterns):
        return False

    retraction_noise_patterns = [
        "story retracted",
        "this story was retracted",
        "this article was retracted",
        "retracted",
        "correction:",
        "corrected:",
        "editor's note:",
        "editors note:",
        "we were wrong",
        "published in error",
        "article has been removed",
        "post has been removed",
        "incorrectly reported",
        "incorrect report",
    ]

    if any(pattern in title_and_summary for pattern in retraction_noise_patterns):
        return False

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
        "conference",
        "annual review",
        "toolkit",
        "advisory",
        "guidance",
        "recommendations",
        "news release",
        "take down",
        "takedown",
        "developer arrest",
        "arrest",
        "seizure",
        "law enforcement",
        "available now",
        "now available",
        "end-to-end encryption",
        "adds infostealer protection",
        "protection against",
        "designed to block",
    ]

    if any(pattern in title for pattern in negative_title_patterns):
        return False

    victim_org_name = _extract_victim_org_name(article)
    has_exploitation_subject = _has_exploitation_signal(text)

    has_reporting_frame = bool(
        re.search(
            r"\b(?:according to|researchers find|report finds|study shows|analysis reveals|researchers say)\b",
            title_and_summary,
            flags=re.IGNORECASE,
        )
    )

    has_direct_attack_construction = bool(
        re.search(
            r"\b(?:"
            r"data breach|security breach|breach of|breach at|hack of|hack at|attack on|attack against|"
            r"hit by ransomware|forced offline|taken offline|"
            r"used in attacks on|used in attacks against|"
            r"hacked to push malware to|push malware to|pushed malware to|"
            r"used to deploy malware|abused to deploy|deployed malware against|deployed malware to|"
            r"stole[n]? data|data leaked|records were accessed|customer data was accessed|"
            r"breached its systems|confirmed a breach|confirmed a cyberattack|confirmed a ransomware attack|"
            r"disclosed a breach|reported a breach|extorted by hackers|following extortion threat"
            r")\b",
            title_and_summary,
            flags=re.IGNORECASE,
        )
    )

    has_completed_incident = any(term in text for term in [
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
        "deployed malware",
        "used to deploy malware",
        "push malware to",
        "pushed malware to",
        "abused to deploy",
    ])

    has_concrete_impact = any(term in text for term in [
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
        "malware",
        "backdoor",
        "infostealer",
        "loader",
        "trojan",
        "wiper",
        "spyware",
    ])

    has_attack_target_context = any(term in text for term in [
        "government",
        "govt",
        "agency",
        "ministry",
        "municipality",
        "city of",
        "county",
        "hospital",
        "hospitals",
        "healthcare",
        "school",
        "schools",
        "university",
        "universities",
        "college",
        "bank",
        "banks",
        "company",
        "companies",
        "organization",
        "organizations",
        "organisation",
        "organisations",
        "website",
        "websites",
        "site",
        "sites",
        "plugin suite",
])

    has_only_advisory_exploitation = (
        _has_exploitation_signal(text)
        and not has_concrete_impact
        and not has_direct_attack_construction
        and not victim_org_name
    )
    if has_only_advisory_exploitation:
        return False

    if victim_org_name:
        return has_direct_attack_construction or has_completed_incident or has_concrete_impact

    if has_exploitation_subject:
        return has_direct_attack_construction or has_completed_incident or has_concrete_impact

    if has_attack_target_context and has_direct_attack_construction:
        return True

    if has_reporting_frame:
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