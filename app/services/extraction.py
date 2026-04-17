import re

from app.extensions import db
from app.models import RawArticle, ArticleExtraction

from app.services.classification import resolve_classification
from app.services.taxonomy import fallback_industry_from_entity_type, normalize_attack_type


def _combined_article_text(article):
    return " ".join(
        [
            (article.title or "").strip(),
            (article.summary or "").strip(),
            (article.content or "").strip(),
        ]
    ).lower()

def _clean_summary_text(value):
    if not value:
        return None

    cleaned = value.strip()
    cleaned = re.sub(r"\s*\[\.\.\.\]\s*$", "", cleaned).strip()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned or None

def _is_plausible_org_candidate(value):
    if not value:
        return False

    cleaned = re.sub(r"\s+", " ", str(value).strip())
    if not cleaned:
        return False

    lowered = cleaned.lower()
    words = lowered.split()

    action_terms = {
        "affects",
        "affected",
        "breached",
        "hacked",
        "hit",
        "targeted",
        "attacked",
        "exposed",
        "leaked",
        "stolen",
        "pushed",
        "push",
        "infected",
        "compromised",
        "extorted",
        "disrupted",
        "running",
        "using",
    }

    generic_tail_terms = {
        "suite",
        "plugin",
        "plugins",
        "package",
        "packages",
        "tool",
        "tools",
        "system",
        "systems",
        "platform",
        "platforms",
        "app",
        "apps",
        "application",
        "applications",
        "sites",
        "website",
        "websites",
        "accounts",
        "users",
        "customers",
        "data",
        "records",
    }

    allowed_org_suffixes = {
        "bank",
        "group",
        "university",
        "hospital",
        "clinic",
        "school",
        "college",
        "telecom",
        "telecommunications",
        "communications",
        "insurance",
        "laboratory",
        "laboratories",
        "agency",
        "ministry",
        "department",
        "authority",
        "city",
        "municipality",
        "network",
        "networks",
        "corp",
        "corporation",
        "inc",
        "ltd",
        "llc",
        "plc",
    }

    if any(term in words for term in action_terms):
        return False

    if len(words) >= 3 and words[-1] in generic_tail_terms and words[-1] not in allowed_org_suffixes:
        return False

    if len(words) >= 2 and words[-2] in action_terms:
        return False

    uppercase_tokens = re.findall(r"\b[A-Z][A-Za-z0-9&._-]*\b", cleaned)
    if not uppercase_tokens and not re.search(r"[A-Z]{2,}", cleaned):
        return False

    return True

ORG_CLAUSE_BOUNDARY_RE = re.compile(
    r"\s+(?:"
    r"affects?|affected|impacting|impacts?|hits?|hit|after|via|through|using|"
    r"linked\s+to|with|in|as|amid|following|from|that|which|where|when|"
    r"according\s+to|said|says|confirmed|confirms|reported|reportedly"
    r")\b",
    flags=re.IGNORECASE,
)

def _clean_org_name(value):
    if not value:
        return None

    cleaned = value.strip(" -,:;\"'()[]{}“”‘’")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    if not cleaned:
        return None

    cleaned = re.sub(r"^(?:the)\s+", "", cleaned, flags=re.IGNORECASE)
    cleaned = ORG_CLAUSE_BOUNDARY_RE.split(cleaned, maxsplit=1)[0].strip()
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" -,:;\"'()[]{}“”‘’")

    if not cleaned:
        return None

    cleaned = re.sub(
        r"^(?:(?:[A-Za-z][A-Za-z0-9&._-]*\s+){0,2}"
        r"(?:company|organization|firm|vendor|provider|developer|publisher|operator|platform|exchange|chain|group|maker|giant)\s+)"
        r"(?=[A-Z])",
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).strip()

    lowered = cleaned.lower()

    blocked_exact = {
        "data",
        "breach",
        "hack",
        "attack",
        "ransomware",
        "cyberattack",
        "cyber",
        "accounts",
        "users",
        "customers",
        "employees",
        "systems",
        "platform",
        "suite",
        "plugin",
        "plugins",
        "report",
        "reports",
        "analysis",
        "hackers",
        "threat actors",
        "official website",
        "download links",
    }

    if not cleaned or lowered in blocked_exact:
        return None

    if len(cleaned) <= 2:
        return None

    if len(cleaned.split()) > 6:
        return None

    if not _is_plausible_org_candidate(cleaned):
        return None

    return cleaned

def _normalize_org_name(value):
    if not value:
        return None

    normalized = value.strip().lower()
    normalized = normalized.replace("-", " ")
    normalized = normalized.replace("&", " and ")
    normalized = re.sub(r"'s\b", "", normalized)
    normalized = re.sub(r"[^a-z0-9\s]", " ", normalized)
    normalized = re.sub(
        r"\b(inc|llc|ltd|corp|corporation|company|co|group|plc|sa|ag|gmbh|nv|bv)\b",
        "",
        normalized,
    )
    normalized = re.sub(r"\s+", " ", normalized).strip()

    return normalized or None

def _classify_org_from_name(org_name):
    if not org_name:
        return None

    lowered = org_name.lower().strip()

    if re.search(
        r"\b(bank of france|banque de france|federal reserve|central bank)\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return "government"

    government_patterns = [
        r"\b(ministry|government|parliament|senate|supreme\s*court|court|municipality|municipal|city of |town of |state department|embassy|agency|department)\b",
        r"\b(army|navy|air force|defence|defense|military)\b",
    ]

    critical_infrastructure_patterns = [
        r"\b(airport|airline|aviation|rail|railway|transit|metro|port authority|shipping|logistics|freight|utility|power grid|power plant|pipeline|water utility|electric company|energy)\b",
    ]

    private_sector_patterns = [
        r"\b(university hospital|hospital|medical center|health system|clinic|health sciences center|bank|credit union|financial|insurance|insurer|exchange|cryptocurrency platform|crypto exchange|telecom|telecommunications|carrier|mobile network|broadband|internet provider|internet service provider|isp|hosting provider|platform|technology|software|newspaper|news outlet|media company|broadcaster|television network|radio station|publisher|university|college|school|schools|school district|public school|public schools|grammar school|campus|research institute|laboratory|research center)\b",
    ]

    for pattern in government_patterns:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return "government"

    for pattern in critical_infrastructure_patterns:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return "critical_infrastructure"

    for pattern in private_sector_patterns:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return "private_sector"

    if re.search(r"\b(inc|corp|corporation|llc|ltd|plc|gmbh|ag|sa|bv|nv)\b", lowered, flags=re.IGNORECASE):
        return "private_sector"

    tokens = lowered.split()
    if len(tokens) == 1 and re.search(r"[a-z]", lowered):
        return "private_sector"

    return None


def _map_entity_type_to_industry(entity_type):
    return fallback_industry_from_entity_type(entity_type)


def _resolve_live_victim_classification(victim_org_name, extracted_industry):
    org_based_entity_type = _classify_org_from_name(victim_org_name)

    if org_based_entity_type:
        resolved = resolve_classification(
            org_lookup_result={
                "victim_entity_type": org_based_entity_type,
                "industry": _map_entity_type_to_industry(org_based_entity_type),
                "source": "live_org_name",
            },
            source_prefix="live",
        )
        if resolved["victim_entity_type"] != "unknown" or resolved["industry"] != "Other":
            return resolved

    return resolve_classification(
        industry_value=extracted_industry,
        source_prefix="live",
    )

def _extract_victim_org_name(article):
    title = (article.title or "").strip()
    summary = (article.summary or "").strip()

    if not title:
        return None

    if title.lower().startswith("webinar:"):
        return None

    texts = [title]
    if summary:
        texts.append(summary)

    target_patterns = [
        r"\b(?:breach|hack|attack|cyberattack|cyber attack|ransomware attack)\s+(?:at|on|against|of)\s+([^,.;:]+)",
        r"\b([^,.;:]+?)\s+(?:was|were|has been|have been)\s+(?:breached|hacked|attacked|targeted|compromised|disrupted|extorted)\b",
        r"\b(?:hit|targeted|breached|hacked|attacked|compromised|disrupted|extorted)\s+([^,.;:]+)",
    ]

    self_disclosure_patterns = [
        r"\b([^,.;:]+?)\s+(?:said|says|confirmed|confirms|announced|disclosed|reported)\b",
    ]

    incident_terms = [
        "breach",
        "data leak",
        "data breach",
        "misconfiguration",
        "hacked",
        "breached",
        "attacked",
        "compromised",
        "ransomware",
        "extortion",
        "leak",
    ]

    blocked_action_phrase = re.compile(
        r"\bto\s+(?:steal|deploy|push|harvest|leak|breach|hack|target|attack|compromise|disrupt|extort)\b",
        flags=re.IGNORECASE,
    )

    for text in texts:
        for pattern in target_patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                candidate = _clean_org_name(match.group(1))
                if not candidate:
                    continue

                if blocked_action_phrase.search(candidate):
                    continue

                return candidate

    for text in texts:
        lowered_text = text.lower()
        if not any(term in lowered_text for term in incident_terms):
            continue

        for pattern in self_disclosure_patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                candidate = _clean_org_name(match.group(1))
                if not candidate:
                    continue

                if blocked_action_phrase.search(candidate):
                    continue

                return candidate

    return None

def _extract_exploitation_subject(article):
    title = (article.title or "").strip()

    if not title:
        return None

    patterns = [
        r"^(?:Critical|High-severity|High severity|Severe|New)\s+([A-Z][A-Za-z0-9._-]*(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+.*\bflaw\b",
        r"^([A-Z][A-Za-z0-9._-]*(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+.*\bflaw\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, title)
        if match:
            candidate = _clean_org_name(match.group(1))
            if candidate:
                return candidate

    return None

def _extract_industry(text):
    target_context_patterns = [
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(government|govt|agency|ministry|municipalit(?:y|ies)|federal|state government|department)\b", "Government"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(hospital|hospitals|healthcare|clinic|health system|medical)\b", "Healthcare"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(school|schools|university|universities|college|education|educational|student|campus|district)\b", "Education"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(bank|banks|financial|credit union|insurance|brokerage|payment processor)\b", "Financial Services"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(utility|utilities|power grid|electric|water utility|pipeline|energy)\b", "Energy"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(airport|airline|aviation|rail|railway|transit|metro|shipping|logistics|freight|port authority)\b", "Transportation"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(newspaper|news outlet|media company|broadcaster|television network|radio station|publisher)\b", "Media"),
    ]

    for pattern, industry in target_context_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return industry

    if any(keyword in text for keyword in [
        "software provider",
        "software vendor",
        "technology",
        "tech company",
        "tech firm",
        "it provider",
        "cloud",
        "saas",
        "hosting provider",
        "managed service provider",
        "msp",
        "it services",
        "data center",
        "software",
        "plugin",
        "browser",
        "developer tool",
        "video game developer",
        "application framework",
        "platform",
        "telematics",
        "fleet management",
        "fleet management company",
        "gps tracking",
        "tracking platform",
    ]):
        return "Technology"

    if any(keyword in text for keyword in [
        "hospital",
        "healthcare",
        "patient",
        "medical",
        "clinic",
        "health system",
        "health service",
    ]):
        return "Healthcare"

    if any(keyword in text for keyword in [
        "bank",
        "banking",
        "financial",
        "atm",
        "cryptocurrency",
        "exchange",
        "fintech",
        "payment processor",
        "credit union",
        "brokerage",
        "insurance",
    ]):
        return "Financial Services"

    if any(keyword in text for keyword in [
        "school",
        "university",
        "college",
        "education",
        "educational",
        "edtech",
        "student",
        "campus",
        "district",
    ]):
        return "Education"

    if any(keyword in text for keyword in [
        "government",
        "agency",
        "ministry",
        "public sector",
        "municipal",
        "city of ",
        "county",
        "state government",
        "federal",
        "department of",
        "public service",
        "township",
        "parish",
    ]):
        return "Government"

    if any(keyword in text for keyword in [
        "energy",
        "utility",
        "power grid",
        "electric",
        "substation",
        "water utility",
        "water treatment",
        "gas utility",
        "pipeline",
    ]):
        return "Energy"

    if any(keyword in text for keyword in [
        "airport",
        "airline",
        "aviation",
        "rail",
        "railway",
        "transit",
        "metro",
        "port authority",
        "shipping",
        "logistics",
        "freight",
    ]):
        return "Transportation"

    if any(keyword in text for keyword in [
        "newspaper",
        "news outlet",
        "media company",
        "broadcaster",
        "television network",
        "radio station",
        "publisher",
    ]):
        return "Media"

    return None

def _extract_geography(text):
    country = None
    region = None

    geography_map = [
        (["united states", "u.s.", "u.s.a.", "usa", "american"], "United States", "North America"),
        (["canada", "canadian"], "Canada", "North America"),
        (["mexico", "mexican"], "Mexico", "North America"),

        (["united kingdom", "uk ", " uk", "britain", "british", "england"], "United Kingdom", "Europe"),
        (["netherlands", "dutch"], "Netherlands", "Europe"),
        (["germany", "german"], "Germany", "Europe"),
        (["france", "french"], "France", "Europe"),
        (["italy", "italian"], "Italy", "Europe"),
        (["spain", "spanish"], "Spain", "Europe"),
        (["portugal", "portuguese"], "Portugal", "Europe"),
        (["belgium", "belgian"], "Belgium", "Europe"),
        (["switzerland", "swiss"], "Switzerland", "Europe"),
        (["austria", "austrian"], "Austria", "Europe"),
        (["poland", "polish"], "Poland", "Europe"),
        (["sweden", "swedish"], "Sweden", "Europe"),
        (["norway", "norwegian"], "Norway", "Europe"),
        (["finland", "finnish"], "Finland", "Europe"),
        (["denmark", "danish"], "Denmark", "Europe"),
        (["ireland", "irish"], "Ireland", "Europe"),
        (["romania", "romanian"], "Romania", "Europe"),
        (["czech republic", "czechia", "czech"], "Czech Republic", "Europe"),
        (["ukraine", "ukrainian"], "Ukraine", "Europe"),
        (["russia", "russian"], "Russia", "Europe"),

        (["china", "chinese"], "China", "Asia"),
        (["taiwan", "taiwanese"], "Taiwan", "Asia"),
        (["japan", "japanese"], "Japan", "Asia"),
        (["india", "indian"], "India", "Asia"),
        (["singapore"], "Singapore", "Asia"),
        (["south korea", "korea", "korean"], "South Korea", "Asia"),
        (["hong kong"], "Hong Kong", "Asia"),
        (["thailand", "thai"], "Thailand", "Asia"),
        (["vietnam", "vietnamese"], "Vietnam", "Asia"),
        (["indonesia", "indonesian"], "Indonesia", "Asia"),
        (["philippines", "philippine"], "Philippines", "Asia"),
        (["malaysia", "malaysian"], "Malaysia", "Asia"),

        (["australia", "australian"], "Australia", "Oceania"),
        (["new zealand"], "New Zealand", "Oceania"),

        (["brazil", "brazilian"], "Brazil", "South America"),
        (["argentina", "argentinian", "argentine"], "Argentina", "South America"),
        (["chile", "chilean"], "Chile", "South America"),
        (["colombia", "colombian"], "Colombia", "South America"),
        (["peru", "peruvian"], "Peru", "South America"),

        (["south africa"], "South Africa", "Africa"),
        (["nigeria", "nigerian"], "Nigeria", "Africa"),
        (["kenya", "kenyan"], "Kenya", "Africa"),
        (["egypt", "egyptian"], "Egypt", "Africa"),

        (["israel", "israeli"], "Israel", "Middle East"),
        (["uae", "united arab emirates"], "United Arab Emirates", "Middle East"),
        (["saudi arabia", "saudi"], "Saudi Arabia", "Middle East"),
        (["qatar"], "Qatar", "Middle East"),
        (["turkey", "turkish"], "Turkey", "Middle East"),
    ]

    target_phrase_patterns = [
        r"\battacks?\s+(?:on|against)\s+([^.;:]+)",
        r"\btarget(?:ing|ed)\s+([^.;:]+)",
        r"\bcampaign(?:s)?\s+against\s+([^.;:]+)",
        r"\bmalware\s+used\s+in\s+attacks?\s+(?:on|against)\s+([^.;:]+)",
    ]

    target_spans = []
    for pattern in target_phrase_patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            span = match.group(1).strip()
            if span:
                target_spans.append(span)

    for span in target_spans:
        for keywords, mapped_country, mapped_region in geography_map:
            if any(keyword in span for keyword in keywords):
                return {
                    "country": mapped_country,
                    "region": mapped_region,
                    "city": None,
                }

    for keywords, mapped_country, mapped_region in geography_map:
        if any(keyword in text for keyword in keywords):
            country = mapped_country
            region = mapped_region
            break

    if country is None:
        region_map = [
            (["north america"], "North America"),
            (["south america", "latin america"], "South America"),
            (["europe", "european"], "Europe"),
            (["asia", "asia-pacific", "apac"], "Asia"),
            (["middle east"], "Middle East"),
            (["africa"], "Africa"),
            (["oceania"], "Oceania"),
            (["global", "worldwide", "international"], "Global"),
        ]

        for keywords, mapped_region in region_map:
            if any(keyword in text for keyword in keywords):
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

    victim_org_name = _extract_victim_org_name(article)
    if victim_org_name is None and _has_exploitation_signal(text):
        victim_org_name = _extract_exploitation_subject(article)

    victim_org_normalized = _normalize_org_name(victim_org_name)
    extracted_industry = _extract_industry(text)
    classification = _resolve_live_victim_classification(
        victim_org_name,
        extracted_industry,
    )

    industry = classification["industry"]

    geography = _extract_geography(text)

    attack_type = "Unknown"
    if any(keyword in text for keyword in [
        "ransomware",
        "ransom note",
        "ransom demand",
        "double extortion",
        "extortion gang",
        "encryptor",
    ]):
        attack_type = "Ransomware"
    elif any(keyword in text for keyword in [
        "phishing",
        "phishing-as-a-service",
        "credential harvesting",
        "spear-phishing",
        "malicious email",
        "business email compromise",
        "bec ",
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
        "breaching systems",
        "breach of",
        "hack at",
        "hack of",
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
        "malicious executables",
        "payload",
        "payloads",
        "deployed payloads",
        "used to deploy malware",
        "abused to deploy",
        "deployed malware",
        "deploy scripts",
        "running with system privileges",
        "disabled antivirus protections",
        "killing scripts",
    ]):
        attack_type = "Malware"
    elif _has_exploitation_signal(text):
        attack_type = "Exploitation"
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

    short_event_summary = _clean_summary_text(article.summary) or _clean_summary_text(article.title)

    attack_type = normalize_attack_type(attack_type)

    return {
        "victim_org_name": victim_org_name,
        "victim_org_normalized": victim_org_normalized,
        "industry": industry,
        "region": geography["region"],
        "country": geography["country"],
        "city": geography["city"],
        "attack_type": attack_type,
        "short_event_summary": short_event_summary,
        "extraction_confidence": None,
    }

def save_extraction(article_id, signals):
    """
    Save thin MVP extraction signals to the database.
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