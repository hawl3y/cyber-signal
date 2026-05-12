import re

from app.extensions import db
from app.models import RawArticle, ArticleExtraction
from app.utils.sources import get_source_config
from app.services.taxonomy import normalize_attack_type, normalize_event_anchor_type


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

def _build_short_event_summary(article):
    summary = _clean_summary_text(article.summary)
    if summary:
        return summary

    title = _clean_summary_text(article.title)
    if title:
        return title

    content = _clean_summary_text(article.content)
    if not content:
        return None

    first_sentence = re.split(r"(?<=[.!?])\s+", content, maxsplit=1)[0].strip()
    return first_sentence or None

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

    cleaned = value.strip(" -,:;\"'[]{}“”‘’")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    if not cleaned:
        return None

    cleaned = re.sub(r"^(?:the)\s+", "", cleaned, flags=re.IGNORECASE)
    cleaned = ORG_CLAUSE_BOUNDARY_RE.split(cleaned, maxsplit=1)[0].strip()
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" -,:;\"'[]{}“”‘’")

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

    cleaned = re.sub(
        r"^([A-Z][A-Za-z0-9&._-]*(?:\s+[A-Z][A-Za-z0-9&._-]*){0,3})\s+[a-z][a-z0-9&._-]*(?:\s+[a-z][a-z0-9&._-]*)*$",
        r"\1",
        cleaned,
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


def _extract_victim_org_name(article):
    title = (article.title or "").strip()
    summary = (article.summary or "").strip()

    if not title:
        return None

    if title.lower().startswith("webinar:"):
        return None

    target_patterns = [
        # Strong: subject of a disclosure verb at the start of the headline.
        # In cyber-news headlines the subject of confirms/discloses/acknowledges/admits
        # is virtually always the victim org.
        r"^\s*([^,.;:]+?)\s+(?:confirms|confirmed|discloses|disclosed|acknowledges|acknowledged|admits|admitted)\b",
        r"\b(?:breach|hack|attack|cyberattack|cyber attack|data theft)\s+at\s+(?:[a-z][a-z0-9&._' -]*\s+){0,5}([A-Z][A-Za-z0-9&._'-]*(?:\s+[A-Z][A-Za-z0-9&._'-]*){0,3})\b",
        r"\b([A-Z][A-Za-z0-9&._'-]*(?:\s+[A-Z][A-Za-z0-9&._'-]*){0,3})\s+hacker\s+claims\s+data\s+theft\b",
        r"\b(?:breach|hack|attack|cyberattack|cyber attack|ransomware attack)\s+(?:at|on|against|of)\s+([^,.;:]+)",
        r"\b(?:breach|attack|cyberattack|cyber attack|ransomware attack)\s+affecting\s+(?:the\s+)?([^,.;:]+)",
        r"\b(?:confirms|confirmed|reports|reported|discloses|disclosed)\s+(?:a\s+)?(?:data\s+)?breach\s+(?:at|of)\s+([^,.;:]+)",
        r"\b([A-Z][A-Za-z0-9&._' -]{1,80}?)\s+(?:confirms|confirmed|acknowledges|acknowledged)\s+(?:the\s+)?(?:incident|cyberattack|cyber attack|attack|breach)\b",
        r"\b([^,.;:]+?)\s+(?:was|were|has been|have been)\s+(?:breached|hacked|attacked|targeted|compromised|disrupted|extorted)\b",
        r"\b([^,.;:]+?)\s+(?:confirms|confirmed|reports|reported|discloses|disclosed)\s+(?:a\s+)?(?:data\s+)?breach\b",
        r"\b([^,.;:]+?)\s+(?:hit by|suffered|suffers)\s+(?:a\s+)?(?:ransomware attack|cyberattack|cyber attack|data breach|security breach)\b",
        r"\b([^,.;:]+?)\s+(?:falls victim to|fell victim to)\s+(?:a\s+)?(?:ransomware attack|cyberattack|cyber attack|data breach|security breach)\b",
    ]

    # Captures ending in audience nouns (e.g. "Armenian users", "Russian citizens")
    # describe who was affected, never the victim org. Drop the whole match.
    audience_tail_re = re.compile(
        r"\b(?:users?|customers?|citizens?|people|visitors?|clients?|"
        r"residents?|nationals?|workers?|members?|subscribers?|patients?|"
        r"students?|employees?|consumers?|tenants?|guests?|riders?|"
        r"shoppers?|viewers?|readers?|listeners?)\s*$",
        flags=re.IGNORECASE,
    )

    blocked_action_phrase = re.compile(
        r"\bto\s+(?:steal|deploy|push|harvest|leak|breach|hack|target|attack|compromise|disrupt|extort)\b",
        flags=re.IGNORECASE,
    )

    generic_org_terms = {
        "agency",
        "bank",
        "company",
        "firm",
        "government",
        "group",
        "hospital",
        "ministry",
        "organization",
        "organisation",
        "provider",
        "school",
        "service",
        "university",
        "vendor",
    }

    def extract_candidates(text):
        candidates = []

        for pattern in target_patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                raw_capture = (match.group(1) or "").strip()
                if audience_tail_re.search(raw_capture):
                    continue

                candidate = _clean_org_name(raw_capture)
                if not candidate:
                    continue

                if blocked_action_phrase.search(candidate):
                    continue

                candidates.append(candidate)

        return candidates

    def is_generic_descriptor(value):
        tokens = value.lower().split()
        if not tokens:
            return True

        if len(tokens) <= 3 and tokens[-1] in generic_org_terms:
            return True

        return False

    title_candidates = extract_candidates(title)
    summary_candidates = extract_candidates(summary) if summary else []

    for candidate in summary_candidates:
        if not is_generic_descriptor(candidate):
            return candidate

    for candidate in title_candidates:
        if not is_generic_descriptor(candidate):
            return candidate

    if summary_candidates:
        return summary_candidates[0]

    if title_candidates:
        return title_candidates[0]

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


def _clean_anchor_candidate(value):
    if not value:
        return None

    cleaned = re.sub(r"\s+", " ", str(value)).strip(" -,:;\"'[]{}“”‘’")

    if not cleaned:
        return None

    if len(cleaned) < 2 or len(cleaned) > 120:
        return None

    blocked = {
        "critical",
        "high-severity",
        "new",
        "severe",
        "flaw",
        "vulnerability",
        "bug",
        "attack",
        "attacks",
        "campaign",
        "ransomware",
        "malware",
    }

    if cleaned.lower() in blocked:
        return None

    return cleaned


def _extract_cisa_vendor(title):
    """
    Extract the vendor name from a CISA advisory title.
    e.g. 'ABB Ability Symphony Plus Engineering' → 'ABB'
         'Johnson Controls CEM AC2000'           → 'Johnson Controls'
         'Hitachi Energy PCM600'                 → 'Hitachi Energy'
    """
    words = title.split()
    if not words:
        return title
    first = words[0]
    # All-caps first word (ABB, NSA, MAXHUB) is a company abbreviation.
    if first.isupper() and len(first) >= 3:
        return first
    # Otherwise take up to 2 words, stopping before product codes
    # (words with digits, all-caps acronyms ≥3 chars, or special chars like &).
    vendor_words = [first]
    if len(words) > 1:
        w = words[1]
        is_product_code = (
            any(c.isdigit() for c in w)
            or (w.isupper() and len(w) >= 3)
            or "&" in w
            or "/" in w
        )
        if not is_product_code:
            vendor_words.append(w)
    return " ".join(vendor_words)


def _extract_event_anchor(article, victim_org_name=None, actor_name=None):
    if victim_org_name:
        return victim_org_name, "organization"

    title = (article.title or "").strip()
    summary = (article.summary or "").strip()
    text = f"{title} {summary}"

    cve_match = re.search(r"\b(CVE-\d{4}-\d+)\b", text, flags=re.IGNORECASE)
    if cve_match:
        return cve_match.group(1).upper(), "vulnerability"

    descriptive_incident_patterns = [
        r"^(.+?)\s+(?:heaped|enabled|launched|conducted|carried out|fueled)\s+attacks?\b",
        r"^(.+?)\s+(?:hit|hits|targeted|attacked|breached|compromised)\b",
    ]

    for pattern in descriptive_incident_patterns:
        match = re.search(pattern, title, flags=re.IGNORECASE)
        if match:
            candidate = _clean_anchor_candidate(match.group(1))
            if candidate:
                return candidate, "campaign"

    campaign_patterns = [
        r"\bin\s+['\"]?([^'\"]+?)['\"]?\s+ransomware\s+attacks?\b",
        r"\b([^,.;:]+?)\s+campaign\b",
    ]

    for pattern in campaign_patterns:
        match = re.search(pattern, title, flags=re.IGNORECASE)
        if match:
            candidate = _clean_anchor_candidate(match.group(1))
            if candidate:
                return candidate, "campaign"

    if article.source_name in {"cisa-kev", "cisa-alerts-advisories"} and title:
        return title, "product_or_platform"

    product_patterns = [
        r"\b(?:flaw|vulnerability|bug)\s+in\s+([^,.;:]+)",
        r"\b([^,.;:]+?)\s+(?:flaw|vulnerability|bug)\b",
        r"\b([^,.;:]+?)\s+(?:zero-day|0-day)\b",
    ]

    for pattern in product_patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            candidate = _clean_anchor_candidate(match.group(1))
            if candidate:
                return candidate, "product_or_platform"

    subject = _extract_exploitation_subject(article)
    if subject:
        return subject, "product_or_platform"

    if actor_name:
        return actor_name, "actor"

    return None, "unknown"


def _extract_industry(text):
    target_context_patterns = [
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(government|govt|agency|ministry|municipalit(?:y|ies)|federal|state government|department)\b", "Government"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(hospital|hospitals|healthcare|clinic|health system|medical)\b", "Healthcare"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(school|schools|university|universities|college|education|educational|student|campus|district)\b", "Education"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(bank|banks|financial|credit union|insurance|brokerage|payment processor)\b", "Financial Services"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(utility|utilities|power grid|water utility|pipeline|energy)\b", "Energy"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(airport|airline|aviation|rail|railway|transit|metro|shipping|logistics|freight|port authority)\b", "Transportation"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(newspaper|news outlet|media company|broadcaster|television network|radio station|publisher)\b", "Media"),
    ]

    for pattern, industry in target_context_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return industry

    organization_type_patterns = [
        (
            r"\b(?:cybersecurity|security|threat intelligence|endpoint security|network security)\s+"
            r"(?:company|firm|vendor|provider|platform)\b",
            "Technology",
        ),
        (
            r"\b(?:company|firm|vendor|provider|platform)\s+"
            r"(?:specializing in|focused on|providing|offering)\s+"
            r"(?:cybersecurity|security|threat intelligence|endpoint security|network security)\b",
            "Technology",
        ),
    ]

    for pattern, industry in organization_type_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return industry

    industry_keywords = {
        "Technology": [
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
            "suite",
            "control panel",
            "platform",
            "plugin",
            "browser",
            "developer tool",
            "application framework",
            "firmware",
            "virtual machines",
            "vendor:",
            "product:",
            "video game developer",
            "telematics",
            "fleet management",
            "fleet management company",
            "gps tracking",
            "tracking platform",
        ],
        "Healthcare": [
            "hospital",
            "healthcare",
            "patient",
            "medical",
            "clinic",
            "health system",
            "health service",
        ],
        "Financial Services": [
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
        ],
        "Education": [
            "school",
            "university",
            "college",
            "education",
            "educational",
            "edtech",
            "student",
            "campus",
            "district",
        ],
        "Government": [
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
        ],
        "Energy": [
            "energy",
            "utility",
            "power grid",
            "substation",
            "water utility",
            "water treatment",
            "gas utility",
            "pipeline",
        ],
        "Transportation": [
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
            "electric bicycle",
            "electric bike",
            "e-bike",
            "ebike",
            "motorcycle",
            "vehicle",
            "automotive",
            "fleet",
        ],
        "Media": [
            "newspaper",
            "news outlet",
            "media company",
            "broadcaster",
            "television network",
            "radio station",
            "publisher",
        ],
    }

    for industry, keywords in industry_keywords.items():
        if any(keyword in text for keyword in keywords):
            return industry

    return None

_COUNTRY_TO_REGION = {
    "United States": "North America",
    "Canada": "North America",
    "Mexico": "North America",
    "United Kingdom": "Europe",
    "Netherlands": "Europe",
    "Germany": "Europe",
    "France": "Europe",
    "Italy": "Europe",
    "Spain": "Europe",
    "Portugal": "Europe",
    "Belgium": "Europe",
    "Switzerland": "Europe",
    "Austria": "Europe",
    "Poland": "Europe",
    "Sweden": "Europe",
    "Norway": "Europe",
    "Finland": "Europe",
    "Denmark": "Europe",
    "Ireland": "Europe",
    "Romania": "Europe",
    "Czech Republic": "Europe",
    "Ukraine": "Europe",
    "Russia": "Europe",
    "China": "Asia",
    "Taiwan": "Asia",
    "Japan": "Asia",
    "India": "Asia",
    "Singapore": "Asia",
    "South Korea": "Asia",
    "Hong Kong": "Asia",
    "Thailand": "Asia",
    "Vietnam": "Asia",
    "Indonesia": "Asia",
    "Philippines": "Asia",
    "Malaysia": "Asia",
    "Australia": "Oceania",
    "New Zealand": "Oceania",
    "Brazil": "South America",
    "Argentina": "South America",
    "Chile": "South America",
    "Colombia": "South America",
    "Peru": "South America",
    "South Africa": "Africa",
    "Nigeria": "Africa",
    "Kenya": "Africa",
    "Egypt": "Africa",
    "Israel": "Middle East",
    "United Arab Emirates": "Middle East",
    "Saudi Arabia": "Middle East",
    "Qatar": "Middle East",
    "Turkey": "Middle East",
    "Iran": "Middle East",
    "Iraq": "Middle East",
    "Jordan": "Middle East",
    "Lebanon": "Middle East",
    "Kuwait": "Middle East",
    "Oman": "Middle East",
    "Bahrain": "Middle East",
    "Yemen": "Middle East",
    "Armenia": "Asia",
    "Azerbaijan": "Asia",
    "Georgia": "Asia",
    "Kazakhstan": "Asia",
    "Pakistan": "Asia",
    "Bangladesh": "Asia",
    "Sri Lanka": "Asia",
    "Nepal": "Asia",
    "Belarus": "Europe",
    "Estonia": "Europe",
    "Latvia": "Europe",
    "Lithuania": "Europe",
    "Slovakia": "Europe",
    "Slovenia": "Europe",
    "Croatia": "Europe",
    "Serbia": "Europe",
    "Bulgaria": "Europe",
    "Hungary": "Europe",
    "Greece": "Europe",
    "Iceland": "Europe",
    "Luxembourg": "Europe",
    "Malta": "Europe",
    "Morocco": "Africa",
    "Algeria": "Africa",
    "Tunisia": "Africa",
    "Ethiopia": "Africa",
    "Ghana": "Africa",
    "Tanzania": "Africa",
    "Zimbabwe": "Africa",
    "Costa Rica": "North America",
    "Panama": "North America",
    "Cuba": "North America",
    "Dominican Republic": "North America",
    "Jamaica": "North America",
    "Venezuela": "South America",
    "Ecuador": "South America",
    "Bolivia": "South America",
    "Uruguay": "South America",
    "Paraguay": "South America",
}


def region_for_country(country):
    """Return the canonical region for a country name, or None if unknown."""
    if not country:
        return None
    return _COUNTRY_TO_REGION.get(country)


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

    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

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

    source_config = get_source_config(article.source_name)
    signal_kind = source_config.get("signal_kind") if source_config else None

    if signal_kind == "activity":
        victim_org_name = None

    victim_org_normalized = _normalize_org_name(victim_org_name)
    victim_context_text = ""
    if victim_org_name:
        parts = [
            article.title or "",
            article.summary or "",
            article.content or "",
        ]
        victim_context_parts = [part for part in parts if victim_org_name.lower() in part.lower()]
        victim_context_text = " ".join(victim_context_parts).lower()

    industry = _extract_industry(victim_context_text) if victim_context_text else None

    if not industry:
        industry = _extract_industry(text)

    if not industry:
        combined_text = " ".join([
            article.title or "",
            article.summary or "",
            article.content or "",
        ]).lower()

        if any(term in combined_text for term in ["hospital", "healthcare", "medical", "medtech", "clinic"]):
            industry = "Healthcare"
        elif any(term in combined_text for term in ["bank", "financial", "fintech", "payment", "credit card"]):
            industry = "Financial Services"
        elif any(term in combined_text for term in ["school", "university", "education", "student"]):
            industry = "Education"
        elif any(term in combined_text for term in ["government", "ministry", "agency", "municipality", "city of"]):
            industry = "Government"
        elif any(term in combined_text for term in ["software vendor", "software provider", "tech company", "tech firm", "saas", "hosting provider", "managed service provider", "msp", "data center", "developer tool", "application framework"]):
            industry = "Technology"

    if not industry:
        industry = "Unknown"

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
        "data theft",
        "stolen data records",
        "stolen records",
        "stole data",
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
    elif any(keyword in text for keyword in [
        "supply chain",
        "malicious package",
        "malicious update",
        "poisoned package",
        "dependency confusion",
        "compromised vendor",
        "third-party compromise",
        "software supply chain",
    ]):
        attack_type = "Supply Chain"
    elif any(keyword in text for keyword in [
        "authentication bypass",
        "auth bypass",
        "improper authentication",
        "broken authentication",
        "bypass authentication",
        "authentication vulnerability",
        "missing authentication",
    ]):
        attack_type = "Authentication Bypass"
    elif any(keyword in text for keyword in [
        "remote code execution",
        "arbitrary code execution",
        "code execution vulnerability",
    ]):
        attack_type = "Remote Code Execution"
    elif any(keyword in text for keyword in [
        "privilege escalation",
        "elevation of privilege",
        "escalate privileges",
        "escalating privileges",
        "local privilege escalation",
    ]):
        attack_type = "Privilege Escalation"
    elif any(keyword in text for keyword in [
        "sql injection",
        "command injection",
        "os command injection",
        "code injection",
        "injection vulnerability",
        "xpath injection",
        "ldap injection",
    ]):
        attack_type = "Injection"
    elif _has_exploitation_signal(text):
        attack_type = "Exploitation"

    short_event_summary = _build_short_event_summary(article)

    attack_type = normalize_attack_type(attack_type)

    signals = {
        "victim_org_name": victim_org_name,
        "victim_org_normalized": victim_org_normalized,
        "industry": industry,
        "region": geography["region"],
        "country": geography["country"],
        "city": geography["city"],
        "attack_type": attack_type,
        "event_signal_type": signal_kind or "incident",
        "short_event_summary": short_event_summary,
        "extraction_confidence": None,
    }

    signals["victim_org_normalized"] = _normalize_org_name(
        signals.get("victim_org_name")
    )

    anchor_name, anchor_type = _extract_event_anchor(
        article,
        victim_org_name=signals.get("victim_org_name"),
        actor_name=signals.get("actor_name"),
    )

    # CVE IDs are clustering anchors, not display entities — leave the label blank
    signals["victim_display_label"] = None if anchor_type == "vulnerability" else anchor_name
    signals["victim_entity_type"] = normalize_event_anchor_type(anchor_type)

    is_cisa_advisory = article.source_name == "cisa-alerts-advisories"
    is_cisa_source = article.source_name in {"cisa-kev", "cisa-alerts-advisories"}
    article_title = (article.title or "").strip()
    clean_substring = (
        anchor_name != article_title
        and len(anchor_name.split()) <= 6
        and anchor_name[:1].isupper()
    )
    if (not signals.get("victim_org_name")
            and anchor_type == "product_or_platform"
            and anchor_name
            and (is_cisa_source or clean_substring)):
        if is_cisa_advisory:
            vendor = _extract_cisa_vendor(anchor_name)
            signals["victim_org_name"] = vendor
            signals["victim_org_normalized"] = _normalize_org_name(vendor)
            signals["victim_display_label"] = vendor
        else:
            signals["victim_org_name"] = anchor_name
            signals["victim_org_normalized"] = _normalize_org_name(anchor_name)
        if signals.get("industry") in (None, "Unknown"):
            signals["industry"] = "Technology"

    return signals


def save_extraction(article_id, signals):
    """
    Save thin MVP extraction signals to the database.
    """
    if not signals.get("victim_org_name"):
        signals["actor_name"] = None
        signals["actor_type"] = None
        signals["attribution_status"] = None

    if not signals.get("actor_name"):
        signals["actor_type"] = None
        signals["attribution_status"] = None
    else:
        if signals.get("attribution_status") == "unknown":
            signals["attribution_status"] = None

    extraction = ArticleExtraction.query.filter_by(raw_article_id=article_id).first()

    if extraction is None:
        extraction = ArticleExtraction(raw_article_id=article_id)
        db.session.add(extraction)

    extraction.victim_org_name = signals.get("victim_org_name")
    extraction.victim_org_normalized = signals.get("victim_org_normalized")
    extraction.victim_display_label = signals.get("victim_display_label")
    extraction.victim_entity_type = signals.get("victim_entity_type")
    extraction.industry = signals.get("industry")
    extraction.region = signals.get("region")
    extraction.country = signals.get("country")
    extraction.city = signals.get("city")
    extraction.attack_type = signals.get("attack_type")
    extraction.short_event_summary = signals.get("short_event_summary")
    extraction.extracted_signals = signals
    extraction.extraction_confidence = signals.get("extraction_confidence")
    extraction.actor_name = signals.get("actor_name")
    extraction.actor_type = signals.get("actor_type")
    extraction.attribution_status = signals.get("attribution_status")

    db.session.commit()
    return extraction


def mark_ready_for_clustering(article):
    """
    Mark article as ready for clustering.
    """
    article.processing_status = "ready_for_clustering"
    db.session.commit()
    return article