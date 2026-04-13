import re
from app.extensions import db
from app.models import RawArticle, ArticleExtraction


def _combined_article_text(article):
    return " ".join(
        [
            (article.title or "").strip(),
            (article.summary or "").strip(),
            (article.content or "").strip(),
        ]
    ).lower()

def _clean_org_name(value):
    if not value:
        return None

    prefixes_to_strip = [
        "cryptocurrency atm giant ",
        "software provider ",
        "software vendor ",
        "healthcare software vendor ",
        "healthcare software provider ",
        "company ",
        "vendor ",
        "provider ",
    ]

    cleaned = value.strip(" -,:;\"'()")

    lowered = cleaned.lower()
    for prefix in prefixes_to_strip:
        if lowered.startswith(prefix):
            cleaned = cleaned[len(prefix):].strip(" -,:;\"'()")
            lowered = cleaned.lower()

    return cleaned or None

def _extract_victim_org_name(article):
    title = (article.title or "").strip()
    lowered = title.lower()

    title_patterns = [
        " reports ",
        " report ",
        " hit by ",
        " attacked by ",
        " breached ",
        " faces ",
        " suffers ",
        " targeted by ",
        " disrupted after ",
        " disrupted by ",
        " affected by ",
        " hacked ",
        " loses ",
        " stolen in ",
    ]

    for pattern in title_patterns:
        if pattern in lowered:
            idx = lowered.find(pattern)
            candidate = _clean_org_name(title[:idx])
            if candidate:
                return candidate

    if " on " in lowered:
        idx = lowered.find(" on ")
        right_side = title[idx + 4:].strip()
        if right_side:
            candidate = _clean_org_name(right_side.split(" after ")[0].split(" by ")[0])
            if candidate and len(candidate.split()) <= 8:
                return candidate

    if ":" in title:
        left = _clean_org_name(title.split(":", 1)[0].strip())
        if left and len(left.split()) <= 8:
            return left

    return None

def _extract_industry(text):
    if any(keyword in text for keyword in ["hospital", "healthcare", "patient", "medical", "clinic"]):
        return "Healthcare"
    if any(keyword in text for keyword in ["bank", "banking", "financial", "atm", "cryptocurrency", "exchange", "fintech"]):
        return "Financial Services"
    if any(keyword in text for keyword in ["school", "university", "college", "education", "student"]):
        return "Education"
    if any(keyword in text for keyword in ["government", "agency", "ministry", "public sector", "municipal"]):
        return "Government"
    if any(keyword in text for keyword in ["software provider", "software vendor", "technology", "tech company", "it provider", "cloud"]):
        return "Technology"
    if any(keyword in text for keyword in ["retail", "store", "merchant", "e-commerce"]):
        return "Retail"
    if any(keyword in text for keyword in ["manufacturer", "manufacturing", "industrial", "factory", "plc"]):
        return "Manufacturing"
    if any(keyword in text for keyword in ["telecom", "telecommunications", "carrier"]):
        return "Telecommunications"
    if any(keyword in text for keyword in ["energy", "utility", "power grid", "electric"]):
        return "Energy"
    return None


def _extract_geography(text):
    country = None
    region = None

    geography_map = [
        (["netherlands", "dutch"], "Netherlands", "Europe"),
        (["united states", "u.s.", "american"], "United States", "North America"),
        (["canada"], "Canada", "North America"),
        (["mexico"], "Mexico", "North America"),
        (["united kingdom", "uk ", "britain", "british", "england"], "United Kingdom", "Europe"),
        (["germany", "german"], "Germany", "Europe"),
        (["france", "french"], "France", "Europe"),
        (["italy", "italian"], "Italy", "Europe"),
        (["spain", "spanish"], "Spain", "Europe"),
        (["ukraine"], "Ukraine", "Europe"),
        (["russia", "russian"], "Russia", "Europe"),
        (["taiwan"], "Taiwan", "Asia"),
        (["china", "chinese"], "China", "Asia"),
        (["japan", "japanese"], "Japan", "Asia"),
        (["india", "indian"], "India", "Asia"),
        (["australia", "australian"], "Australia", "Oceania"),
    ]

    for keywords, mapped_country, mapped_region in geography_map:
        if any(keyword in text for keyword in keywords):
            country = mapped_country
            region = mapped_region
            break

    return {
        "country": country,
        "region": region,
        "city": None,
    }

def _has_exploitation_signal(text):
    if not text:
        return False

    patterns = [
        r"\bcve-\d{4}-\d+\b",
        r"\bexploit\b",
        r"\bexploited\b",
        r"\bexploitation\b",
        r"\bactively exploited\b",
        r"\bunder active exploitation\b",
        r"\bknown exploited vulnerability\b",
        r"\bpre-auth\b",
        r"\bremote code execution\b",
        r"\brce\b",
    ]

    return any(re.search(pattern, text) for pattern in patterns)

def get_ready_for_extraction():
    """
    Fetch articles ready for extraction.
    """
    return RawArticle.query.filter_by(processing_status="ready_for_extraction").all()

def run_rule_extraction(article):
    """
    First-pass deterministic extraction from article text.
    """
    text = _combined_article_text(article)
    access_text = " ".join(
        [
            (article.title or "").strip(),
            (article.summary or "").strip(),
        ]
    ).lower()

    victim_org_name = _extract_victim_org_name(article)
    victim_org_normalized = victim_org_name.lower() if victim_org_name else None
    industry = _extract_industry(text)
    geography = _extract_geography(text)

    attack_type = "Unknown"
    if any(keyword in text for keyword in [
        "ransomware",
        "ransom note",
        "ransom demand",
        "double extortion",
        "extortion gang",
    ]):
        attack_type = "Ransomware"
    elif any(keyword in text for keyword in [
        "phishing",
        "phishing-as-a-service",
        "credential harvesting",
        "spear-phishing",
        "malicious email",
    ]):
        attack_type = "Phishing"
    elif any(keyword in text for keyword in [
        "ddos",
        "denial of service",
        "distributed denial of service",
        "botnet",
        "traffic flood",
    ]):
        attack_type = "DDoS"
    elif any(keyword in text for keyword in [
        "data breach",
        "security breach",
        "breached",
        "exposed data",
        "data exposed",
        "unauthorized access to data",
        "customer data was accessed",
        "records were accessed",
    ]):
        attack_type = "Data Breach"
    elif any(keyword in text for keyword in [
        "malware",
        "trojan",
        "infostealer",
        "backdoor",
        "loader",
        "spyware",
        "wiper",
    ]):
        attack_type = "Malware"
    elif any(keyword in text for keyword in [
        "credential theft",
        "stolen credentials",
        "account takeover",
        "compromised account",
        "hijacked account",
        "accounts were compromised",
        "obtained control of credentials",
    ]):
        attack_type = "Account Compromise"
    elif _has_exploitation_signal(text):
        attack_type = "Exploitation"

    access_vector = None
    if any(keyword in access_text for keyword in [
        "phishing",
        "spear-phishing",
        "phishing email",
        "phishing campaign",
        "phishing message",
        "malicious email",
    ]):
        access_vector = "Phishing"
    elif any(keyword in access_text for keyword in [
        "business email compromise",
        "bec ",
        "email",
        "mailbox",
        "gmail",
        "inbox",
        "email account",
    ]):
        access_vector = "Email"
    elif any(keyword in access_text for keyword in [
        "vpn",
        "remote access",
        "rdp",
        "remote desktop",
        "citrix",
        "remote management",
        "externally exposed service",
    ]):
        access_vector = "Remote Access"
    elif any(keyword in access_text for keyword in [
        "credential",
        "credentials",
        "login",
        "logins",
        "account takeover",
        "obtained control of credentials",
        "stolen credentials",
        "compromised account",
        "hijacked account",
        "password reset",
        "valid account",
        "valid accounts",
        "credential stuffing",
    ]):
        access_vector = "Credential Abuse"
    elif _has_exploitation_signal(access_text):
        access_vector = "Exploitation"
    elif any(keyword in access_text for keyword in [
        "router",
        "routers",
        "network device",
        "appliance",
        "firewall",
        "gateway",
        "plc",
        "industrial device",
        "edge device",
        "vpn appliance",
    ]):
        access_vector = "Network Device"
    elif any(keyword in access_text for keyword in [
        "website",
        "web site",
        "web portal",
        "browser",
        "download link",
        "official website",
        "web app",
        "web application",
        "internet-facing application",
    ]):
        access_vector = "Web"
    elif attack_type == "Phishing":
        access_vector = "Phishing"
    elif attack_type == "Account Compromise":
        access_vector = "Credential Abuse"
    elif attack_type == "Exploitation":
        access_vector = "Exploitation"
    elif attack_type == "Ransomware":
        access_vector = "Unknown Initial Access"

    impact_type = None
    if any(keyword in text for keyword in [
        "disruption",
        "service disruption",
        "outage",
        "downtime",
        "forced offline",
        "taken offline",
        "operations were disrupted",
        "shutdown",
    ]):
        impact_type = "Operational Disruption"
    elif any(keyword in text for keyword in [
        "stolen",
        "exfiltrat",
        "data leak",
        "data leaked",
        "data was accessed",
        "records were accessed",
        "information was stolen",
        "credential theft",
    ]):
        impact_type = "Data Theft"
    elif any(keyword in text for keyword in [
        "extortion",
        "ransom demand",
        "blackmail",
        "double extortion",
    ]):
        impact_type = "Extortion"
    elif any(keyword in text for keyword in [
        "fraud",
        "wire fraud",
        "payment diversion",
        "financial losses",
        "funds were stolen",
    ]) or ("stolen" in text and "$" in text):
        impact_type = "Financial Loss"
    elif any(keyword in text for keyword in [
        "obtained control of credentials",
        "account takeover",
        "compromised account",
        "hijacked account",
        "accounts were compromised",
    ]):
        impact_type = "Account Compromise"

    if impact_type is None:
        if attack_type == "Ransomware":
            impact_type = "Extortion"
        elif attack_type == "DDoS":
            impact_type = "Operational Disruption"
        elif attack_type == "Data Breach":
            impact_type = "Data Theft"
        elif attack_type == "Account Compromise":
            impact_type = "Account Compromise"

    vuln_status = "unknown"
    if (
        "cve-" in text
        or "vulnerability" in text
        or "actively exploited" in text
        or "under active exploitation" in text
        or "known exploited vulnerability" in text
    ):
        vuln_status = "known_vulnerability"

    zero_day_flag = "zero-day" in text or "0day" in text or "0-day" in text

    short_event_summary = (article.summary or article.title or "").strip()

    return {
        "victim_org_name": victim_org_name,
        "victim_org_normalized": victim_org_normalized,
        "industry": industry,
        "region": geography["region"],
        "country": geography["country"],
        "city": geography["city"],
        "attack_type": attack_type,
        "access_vector": access_vector,
        "impact_type": impact_type,
        "actor_name": None,
        "actor_type": None,
        "attribution_status": "unattributed",
        "vuln_status": vuln_status,
        "cve_ids": [],
        "zero_day_flag": zero_day_flag,
        "short_event_summary": short_event_summary,
        "extraction_confidence": 0.5,
    }

def run_ai_extraction(article):
    """
    Placeholder AI extraction.
    """
    return {}


def merge_signals(rule_signals, ai_signals):
    """
    Merge extraction results.
    """
    merged = {}
    merged.update(rule_signals)
    merged.update(ai_signals)
    return merged


def save_extraction(article_id, signals):
    """
    Save extracted signals to the database.
    """
    extraction = ArticleExtraction.query.filter_by(raw_article_id=article_id).first()

    if extraction is None:
        extraction = ArticleExtraction(raw_article_id=article_id)
        db.session.add(extraction)

    extraction.victim_org_name = signals.get("victim_org_name")
    extraction.victim_org_normalized = signals.get("victim_org_normalized")
    extraction.industry = signals.get("industry")
    extraction.region = signals.get("region")
    extraction.country = signals.get("country")
    extraction.city = signals.get("city")
    extraction.attack_type = signals.get("attack_type")
    extraction.access_vector = signals.get("access_vector")
    extraction.impact_type = signals.get("impact_type")
    extraction.actor_name = signals.get("actor_name")
    extraction.actor_type = signals.get("actor_type")
    extraction.attribution_status = signals.get("attribution_status")
    extraction.vuln_status = signals.get("vuln_status")
    extraction.cve_ids = signals.get("cve_ids")
    extraction.zero_day_flag = signals.get("zero_day_flag", False)
    extraction.short_event_summary = signals.get("short_event_summary")
    extraction.extracted_signals = signals
    extraction.extraction_confidence = signals.get("extraction_confidence")

    db.session.commit()
    return extraction


def mark_ready_for_clustering(article):
    """
    Mark article as ready for clustering.
    """
    article.processing_status = "ready_for_clustering"
    db.session.commit()
    return article