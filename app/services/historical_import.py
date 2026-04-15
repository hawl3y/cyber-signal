import ast
import csv
import re
from datetime import datetime
from pathlib import Path


def _parse_eurepoc_date(value):
    if not value:
        return None

    value = str(value).strip()

    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


def _normalize_org_name(value):
    if not value:
        return None

    normalized = value.strip().lower()
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

def _clean_eurepoc_value(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    lowered = value.lower()
    if lowered in ["not available", "unknown", "none", "nan"]:
        return None

    return value


def _pick_first_meaningful_semicolon_value(value):
    """
    EuRepoC often stores repeated or unpacked values separated by semicolons.
    Keep the first meaningful unique value.
    """
    value = _clean_eurepoc_value(value)
    if not value:
        return None

    parts = [part.strip() for part in value.split(";") if part.strip()]
    cleaned_parts = []

    for part in parts:
        cleaned = _clean_eurepoc_value(part)
        if cleaned and cleaned not in cleaned_parts:
            cleaned_parts.append(cleaned)

    if not cleaned_parts:
        return None

    return cleaned_parts[0]

def _clean_semicolon_values(value):
    """
    Return a de-duplicated list of meaningful semicolon-separated values.
    """
    value = _clean_eurepoc_value(value)
    if not value:
        return []

    parts = [part.strip() for part in value.split(";") if part.strip()]
    cleaned_parts = []

    for part in parts:
        cleaned = _clean_eurepoc_value(part)
        if cleaned and cleaned not in cleaned_parts:
            cleaned_parts.append(cleaned)

    return cleaned_parts

def _normalize_placeholder_name(value):
    value = _pick_first_meaningful_semicolon_value(value)
    if not value:
        return None

    lowered = value.strip().lower()

    placeholder_values = {
        "unknown",
        "not available",
        "not attributed",
        "unattributed",
        "n/a",
        "none",
    }

    if lowered in placeholder_values:
        return None

    return value.strip()

def _truncate_string(value, max_length):
    if value is None:
        return None

    value = str(value).strip()
    if not value:
        return None

    if len(value) <= max_length:
        return value

    return value[: max_length - 1].rstrip()

def _simplify_receiver_category(value):
    values = _clean_semicolon_values(value)
    if not values:
        return None

    lowered_values = [item.lower() for item in values]

    if any("corporate" in item or "private sector" in item or "company" in item or "business" in item for item in lowered_values):
        return "private_sector"

    if any("end user" in item or "specially protected groups" in item or "individual" in item for item in lowered_values):
        return "individuals"

    if any("media" in item or "journalism" in item or "news" in item or "newspaper" in item for item in lowered_values):
        return "media"

    if any("social groups" in item or "activists" in item or "advocacy" in item or "human rights" in item for item in lowered_values):
        return "civil_society"

    if any("critical infrastructure" in item for item in lowered_values):
        return "critical_infrastructure"

    if any("international" in item or "supranational" in item or "humanitarian" in item for item in lowered_values):
        return "international"

    if any("science" in item or "research" in item for item in lowered_values):
        return "research"

    if any("health" in item or "hospital" in item or "medical" in item for item in lowered_values):
        return "healthcare"

    if any("education" in item or "university" in item or "school" in item for item in lowered_values):
        return "education"

    if any("state institutions" in item or "political system" in item or "government" in item for item in lowered_values):
        return "public_sector"

    return None


def _simplify_receiver_subcategory(value):
    values = _clean_semicolon_values(value)
    if not values:
        return None

    normalized_values = []
    for item in values:
        cleaned = re.sub(r"\s*\(e\.g\.[^)]+\)", "", item, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if cleaned:
            normalized_values.append(cleaned)

    if not normalized_values:
        return None

    generic_map = {
        "other targets": None,
        "other": None,
        "unknown": None,
        "health": "Healthcare organizations",
        "transportation": "Transportation organizations",
        "transport": "Transportation organizations",
        "finance": "Financial institutions",
        "financial": "Financial institutions",
        "legislative": "Legislative bodies",
        "government / ministries": "Government entities",
        "civil service / administration": "Civil administration",
        "media targets": "Media organizations",
        "social groups targets": "Civil society organizations",
        "advocacy / activists": "Advocacy organizations",
        "political parties": "Political parties",
        "military": "Military organizations",
        "defence industry": "Defense industry organizations",
        "defense industry": "Defense industry organizations",
        "election infrastructure / related systems": "Election systems",
        "critical infrastructure": "Critical infrastructure organizations",
        "energy": "Critical infrastructure organizations",
        "telecommunications": "Technology organizations",
    }

    mapped_values = []
    for item in normalized_values:
        lowered = item.lower()
        mapped = generic_map.get(lowered, item)
        if mapped and mapped not in mapped_values:
            mapped_values.append(mapped)

    if not mapped_values:
        return None

    priority_order = [
        "Political parties",
        "Media organizations",
        "Military organizations",
        "Financial institutions",
        "Transportation organizations",
        "Healthcare organizations",
        "Educational institutions",
        "Technology organizations",
        "Defense industry organizations",
        "Critical infrastructure organizations",
        "Government entities",
        "Civil administration",
        "Legislative bodies",
        "Election systems",
        "Advocacy organizations",
        "Civil society organizations",
    ]

    for candidate in priority_order:
        if candidate in mapped_values:
            return candidate

    return mapped_values[0]


def _build_target_fallback_label(category_family, subcategory, country):
    if subcategory:
        base_label = subcategory
    else:
        category_defaults = {
            "public_sector": "Public sector entities",
            "critical_infrastructure": "Critical infrastructure organizations",
            "private_sector": "Private sector organizations",
            "media": "Media organizations",
            "civil_society": "Civil society organizations",
            "international": "International organizations",
            "individuals": "Individual targets",
            "research": "Research organizations",
            "healthcare": "Healthcare organizations",
            "education": "Educational institutions",
        }
        base_label = category_defaults.get(category_family, "Unspecified target")

    if country:
        return f"{base_label} ({country})"

    return base_label


def _infer_target_type_from_text(title, summary):
    text = " ".join(
        [
            str(title or ""),
            str(summary or ""),
        ]
    ).lower()

    strong_media_terms = [
        "state television",
        "state tv",
        "broadcaster",
        "news outlet",
        "news agency",
        "media outlet",
        "al jazeera",
        "india today",
        "zeenews",
        "spiegel",
        "tv station",
        "television station",
        "military news agency",
    ]

    if any(term in text for term in strong_media_terms):
        return "media"

    if any(
        term in text
        for term in [
            "political party",
            "political parties",
            "kuomintang",
            "democratic progressive party",
            "dpp",
            "party headquarters",
            "presidential campaign",
            "campaign for president",
            "election commission",
            "electoral",
        ]
    ):
        return "political"

    if any(
        term in text
        for term in [
            "military",
            "naval",
            "air force",
            "war college",
            "army",
            "defense ministry",
            "defence ministry",
            "defense department",
            "defence department",
            "navy",
            "centrifuges",
            "nuclear facility",
            "niprnet",
            "bundeswehr",
        ]
    ):
        return "military"

    if any(
        term in text
        for term in [
            "swift",
            "bank",
            "payment system",
            "financial institution",
            "credit union",
            "central bank",
        ]
    ):
        return "financial"

    if any(
        term in text
        for term in [
            "airline",
            "airport",
            "transport",
            "rail",
            "shipping",
            "port authority",
            "metro",
            "railway",
            "aeroflot",
        ]
    ):
        return "transportation"

    if any(
        term in text
        for term in [
            "hospital",
            "medical center",
            "healthcare",
            "health system",
            "clinic",
            "medical facility",
        ]
    ):
        return "healthcare"

    if any(
        term in text
        for term in [
            "university",
            "college",
            "school",
            "campus",
            "research institute",
            "laboratory",
            "research center",
            "scientific institute",
        ]
    ):
        return "education"

    if any(
        term in text
        for term in [
            "westinghouse",
            "us steel",
            "lockheed martin",
            "commercial and defense technology companies",
            "technology companies",
            "defense technology companies",
            "company",
            "corporation",
            "enterprise",
            "business",
            "manufacturer",
            "industrial",
            "defense contractor",
            "contractor",
            "technology theft",
        ]
    ):
        return "private_sector"

    if any(
        term in text
        for term in [
            "muslims",
            "internet users",
            "users",
            "activist",
            "activists",
            "advocacy",
            "civil society",
            "human rights",
            "nonprofit",
            "non-profit",
            "ngo",
            "social movement",
            "humanitarian organization",
        ]
    ):
        return "individuals"

    if any(
        term in text
        for term in [
            "government website",
            "government websites",
            "state department",
            "government agency",
            "federal agency",
            "ministry",
            "embassy",
            "parliament",
            "senate",
            "municipality",
            "city government",
            "government",
        ]
    ):
        return "government"

    if any(
        term in text
        for term in [
            "electric company",
            "power grid",
            "power plant",
            "pipeline",
            "water utility",
            "utility company",
        ]
    ):
        return "critical_infrastructure"

    if any(
        term in text
        for term in [
            "website",
            "websites",
            "web site",
            "web sites",
            "webpage",
            "webpages",
            "web host",
            "hosting provider",
            "mobile app",
            "smartphone",
            "app store",
            "platform",
            "online service",
            "cyber war",
            "cyberwar",
            "defacing web",
        ]
    ):
        return "technology"

    if any(
        term in text
        for term in [
            "newspaper",
            "newspapers",
            "journalist",
        ]
    ):
        return "media"

    return None


def _classify_target(
    receiver_name,
    receiver_category,
    receiver_subcategory,
    receiver_country,
    title,
    summary,
):
    name = _normalize_placeholder_name(receiver_name)
    subcategory = _simplify_receiver_subcategory(receiver_subcategory)
    category_family = _simplify_receiver_category(receiver_category)
    country = _pick_first_meaningful_semicolon_value(receiver_country)

    subcategory_target_map = {
        "Healthcare organizations": "healthcare",
        "Transportation organizations": "transportation",
        "Financial institutions": "financial",
        "Legislative bodies": "government",
        "Government entities": "government",
        "Civil administration": "government",
        "Media organizations": "media",
        "Civil society organizations": "civil_society",
        "Advocacy organizations": "civil_society",
        "Political parties": "political",
        "Military organizations": "military",
        "Defense industry organizations": "private_sector",
        "Election systems": "political",
        "Critical infrastructure organizations": "critical_infrastructure",
        "Technology organizations": "technology",
    }

    category_target_map = {
        "public_sector": "government",
        "critical_infrastructure": "critical_infrastructure",
        "private_sector": "private_sector",
        "media": "media",
        "civil_society": "civil_society",
        "international": "international",
        "individuals": "individuals",
        "research": "research",
        "healthcare": "healthcare",
        "education": "education",
    }

    target_type = None
    source = None
    inferred = _infer_target_type_from_text(title, summary)

    if subcategory:
        mapped = subcategory_target_map.get(subcategory)
        if mapped:
            if mapped in {"civil_society", "government", "critical_infrastructure", "media"} and inferred in {
                "media",
                "political",
                "military",
                "financial",
                "transportation",
                "private_sector",
                "technology",
                "individuals",
            } and inferred != mapped:
                target_type = inferred
                source = "text_inference_override_subcategory"
            else:
                target_type = mapped
                source = "receiver_subcategory"

    if not target_type and category_family:
        mapped = category_target_map.get(category_family)
        if mapped:
            if mapped in {"civil_society", "government", "critical_infrastructure", "media"} and inferred in {
                "media",
                "political",
                "military",
                "financial",
                "transportation",
                "private_sector",
                "technology",
                "individuals",
            } and inferred != mapped:
                target_type = inferred
                source = "text_inference_override_category"
            else:
                target_type = mapped
                source = "receiver_category"

    if not target_type and inferred:
        target_type = inferred
        source = "text_inference"

    if not target_type:
        target_type = "unknown"
        source = "fallback"

    return {
        "receiver_name": name,
        "receiver_subcategory": subcategory,
        "receiver_category_family": category_family,
        "country": country,
        "target_type": target_type,
        "source": source,
    }


def _build_victim_label_from_target(target):
    name = target.get("receiver_name")
    if name:
        return name

    country = target.get("country")
    target_type = target.get("target_type")

    label_map = {
        "government": "Government entities",
        "political": "Political parties",
        "military": "Military organizations",
        "media": "Media organizations",
        "financial": "Financial institutions",
        "transportation": "Transportation organizations",
        "healthcare": "Healthcare organizations",
        "education": "Educational institutions",
        "civil_society": "Civil society organizations",
        "technology": "Technology organizations",
        "critical_infrastructure": "Critical infrastructure organizations",
        "private_sector": "Private sector organizations",
        "research": "Research organizations",
        "international": "International organizations",
        "individuals": "Individual targets",
        "unknown": "Unspecified target",
    }

    base_label = label_map.get(target_type, "Unspecified target")
    return f"{base_label} ({country})" if country else base_label


def _map_industry_from_target(target):
    target_type = target.get("target_type")

    industry_map = {
        "government": "Government",
        "political": "Government",
        "military": "Government",
        "media": "Media",
        "financial": "Financial Services",
        "transportation": "Transportation",
        "healthcare": "Healthcare",
        "education": "Education",
        "civil_society": "Other",
        "technology": "Technology",
        "critical_infrastructure": "Energy",
        "private_sector": "Private Sector",
        "research": "Education",
        "international": "Other",
        "individuals": "Other",
        "unknown": "Other",
    }

    return industry_map.get(target_type, "Other")


def _derive_victim_label(receiver_name, receiver_category, receiver_subcategory, receiver_country, title=None, summary=None):
    target = _classify_target(
        receiver_name,
        receiver_category,
        receiver_subcategory,
        receiver_country,
        title,
        summary,
    )
    return _build_victim_label_from_target(target)


def _parse_region_list(value):
    value = _clean_eurepoc_value(value)
    if not value:
        return None

    direct_map = {
        "oc": "Oceania",
        "oceania": "Oceania",
        "eu": "Europe",
        "na": "North America",
        "north america": "North America",
        "sa": "South America",
        "south america": "South America",
        "af": "Africa",
        "africa": "Africa",
        "as": "Asia",
        "asia": "Asia",
        "me": "Middle East",
        "middle east": "Middle East",
    }

    invalid_values = {
        "not available",
        "unknown",
        "none",
        "nan",
        "nato",
    }

    try:
        parsed = ast.literal_eval(value)
        if isinstance(parsed, list) and parsed:
            region_map = {
                "EUROPE": "Europe",
                "EASTEU": "Europe",
                "WESTEU": "Europe",
                "NORTHAM": "North America",
                "LATAM": "South America",
                "ASIA": "Asia",
                "EASTASIA": "Asia",
                "SOUTHASIA": "Asia",
                "MIDEAST": "Middle East",
                "AFRICA": "Africa",
                "OCEANIA": "Oceania",
                "OC": "Oceania",
            }

            for item in parsed:
                item_str = str(item).strip()
                if not item_str:
                    continue

                lowered = item_str.lower()
                if lowered in invalid_values:
                    continue

                mapped = region_map.get(item_str.upper()) or direct_map.get(lowered)
                if mapped:
                    return mapped

                return None
    except (ValueError, SyntaxError):
        lowered = value.lower().strip()
        if lowered in invalid_values:
            return None
        return direct_map.get(lowered)

    return None


def _map_industry(receiver_name, receiver_category, receiver_subcategory, receiver_country, title=None, summary=None):
    target = _classify_target(
        receiver_name,
        receiver_category,
        receiver_subcategory,
        receiver_country,
        title,
        summary,
    )
    return _map_industry_from_target(target)


def _map_attack_and_impact(incident_type, has_disruption, data_theft, hijacking, title=None, description=None):
    text = " ".join(
        [
            str(incident_type or ""),
            str(title or ""),
            str(description or ""),
        ]
    ).lower()

    disruption_text = str(has_disruption or "").lower()
    theft_text = str(data_theft or "").lower()
    hijacking_text = str(hijacking or "").lower()

    disruption_signal = any(
        term in text
        for term in [
            "disruption",
            "ddos",
            "deface",
            "defacement",
            "outage",
            "offline",
            "shutdown",
            "shut down",
            "encrypted",
            "encryption",
            "ransom note",
            "destroyed",
            "destruction",
            "worm",
            "sabotage",
        ]
    ) or ("true" in disruption_text or "long-term disruption" in disruption_text)

    theft_signal = any(
        term in text
        for term in [
            "data theft",
            "data breach",
            "breach",
            "leak",
            "leaked",
            "exfil",
            "stole",
            "stolen",
            "wiretap",
            "spied",
            "espionage",
        ]
    ) or any(
        term in theft_text for term in ["data breach", "leaking", "theft", "stolen", "exfil"]
    )

    hijack_signal = any(
        term in text
        for term in [
            "hijacking",
            "account compromise",
            "account takeover",
            "credential theft",
            "stolen credentials",
            "compromised account",
        ]
    ) or "hijacking" in hijacking_text

    ransomware_signal = "ransomware" in text

    if ransomware_signal:
        attack_type = "Ransomware"
    elif disruption_signal and not theft_signal:
        attack_type = "Disruption"
    elif theft_signal:
        attack_type = "Data Breach"
    elif hijack_signal:
        attack_type = "Account Compromise"
    elif disruption_signal:
        attack_type = "Disruption"
    else:
        attack_type = "Unknown"

    if ransomware_signal:
        impact_type = "Data Theft" if theft_signal else "Operational Disruption"
    elif disruption_signal and not theft_signal:
        impact_type = "Operational Disruption"
    elif theft_signal:
        impact_type = "Data Theft"
    elif hijack_signal:
        impact_type = "Account Compromise"
    elif disruption_signal:
        impact_type = "Operational Disruption"
    else:
        impact_type = None

    return attack_type, impact_type


def _map_attribution_status(attribution_type, settled_initiator, initiator_name):
    attribution_text = str(attribution_type or "").lower()
    settled_text = str(settled_initiator or "").lower()
    initiator_text = _normalize_placeholder_name(initiator_name)

    if not initiator_text:
        return "unattributed"

    if "true" in settled_text:
        return "attributed"

    if "direct" in attribution_text or "official" in attribution_text:
        return "attributed"

    if "claimed" in attribution_text or "suspected" in attribution_text or "alleged" in attribution_text:
        return "claimed"

    return "claimed"


def _map_actor_type(initiator_category, initiator_name=None):
    category = str(initiator_category or "").lower()
    name = (_normalize_placeholder_name(initiator_name) or "").lower()

    if not category and not name:
        return None

    if any(term in name for term in ["group", "union", "collective", "crew", "gang", "ransom"]):
        return "Threat Group"

    if "hacktivist" in category:
        return "Hacktivist"

    if "cybercrime" in category or "criminal" in category:
        return "Cybercrime Group"

    if "state" in category and name:
        return "State Actor"

    return None


def _derive_verification_level(source_disclosure, attribution_type):
    disclosure = (source_disclosure or "").lower()
    attribution = (attribution_type or "").lower()

    if (
        "authorities" in disclosure
        or "victim state" in disclosure
        or "receiver government" in attribution
        or "direct statement" in attribution
    ):
        return "high"

    if disclosure or attribution:
        return "medium"

    return "low"

def _derive_vuln_status(zero_days, mitre_initial_access):
    zero_days_value = _clean_eurepoc_value(zero_days)
    mitre_value = _clean_eurepoc_value(mitre_initial_access)

    if _derive_zero_day_flag(zero_days_value):
        return "known_vulnerability"

    if mitre_value and any(
        term in mitre_value.lower()
        for term in ["exploit", "vulnerability", "public-facing application", "drive-by compromise"]
    ):
        return "known_vulnerability"

    return "unknown"


def _derive_zero_day_flag(zero_days):
    zero_days_value = _clean_eurepoc_value(zero_days)
    if not zero_days_value:
        return False

    lowered = zero_days_value.lower()

    if lowered in ["not available", "none", "false", "0"]:
        return False

    return "zero" in lowered or "0day" in lowered or "0-day" in lowered


def _derive_is_high_impact(weighted_intensity, impact_indicator_score, has_disruption, data_theft):
    try:
        if weighted_intensity and float(weighted_intensity) >= 4:
            return True
    except ValueError:
        pass

    try:
        if impact_indicator_score and float(impact_indicator_score) >= 8:
            return True
    except ValueError:
        pass

    if "true" in str(has_disruption or "").lower():
        return True

    if "data breach" in str(data_theft or "").lower():
        return True

    return False


def _clean_summary(description):
    if not description:
        return None

    text = re.sub(r"\[[0-9]+\]", "", description)
    text = re.sub(r"\s+", " ", text).strip()

    return text[:500].rstrip() if len(text) > 500 else text

def _postprocess_mapped_event(event):
    title = str(event.get("canonical_title") or "").lower()
    summary = str(event.get("summary_short") or "").lower()
    combined = f"{title} {summary}"

    disruption_signals = [
        "turned off internet access",
        "shut down",
        "offline",
        "defaced",
        "ddos",
        "destruction",
        "replaced",
        "took down",
        "sluggish",
        "counter attacked",
    ]

    if any(term in combined for term in disruption_signals):
        event["attack_type"] = "Disruption"
        event["impact_type"] = "Operational Disruption"

    return event


def map_eurepoc_row_to_cyber_event(row):
    target = _classify_target(
        row.get("receiver_name"),
        row.get("receiver_category"),
        row.get("receiver_subcategory"),
        row.get("receiver_country"),
        row.get("name"),
        row.get("description"),
    )
    victim_display_label = _build_victim_label_from_target(target)
    victim_entity_type = target.get("target_type")

    receiver_name = target.get("receiver_name")

    victim_org_name = receiver_name
    victim_org_normalized = _normalize_org_name(receiver_name) if receiver_name else None

    attack_type, impact_type = _map_attack_and_impact(
        row.get("incident_type"),
        row.get("has_disruption"),
        row.get("data_theft"),
        row.get("hijacking"),
        row.get("name"),
        row.get("description"),
    )

    actor_name = _truncate_string(
        _normalize_placeholder_name(row.get("initiator_name")),
        255,
    )

    country = _pick_first_meaningful_semicolon_value(row.get("receiver_country"))
    region = _parse_region_list(row.get("receiver_regions"))

    zero_days_value = row.get("zero_days")
    mitre_initial_access = row.get("mitre_initial_access")

    event = {
        "slug": f"eurepoc-{row['incident_id']}",
        "canonical_title": row.get("name") or f"EuRepoC incident {row['incident_id']}",
        "event_status": "historical",
        "verification_level": _derive_verification_level(
            row.get("source_disclosure"),
            row.get("attribution_type"),
        ),
        "record_origin": "historical_dataset",
        "confidence_level": "high",
        "confidence_score": None,
        "event_occurred_at": _parse_eurepoc_date(row.get("start_date")),
        "victim_org_name": victim_org_name,
        "victim_org_normalized": victim_org_normalized,
        "victim_entity_type": victim_entity_type,
        "victim_display_label": victim_display_label,
        "industry": _map_industry_from_target(target),
        "attack_type": attack_type,
        "access_vector": None,
        "impact_type": impact_type,
        "actor_name": actor_name,
        "actor_type": _map_actor_type(
            _clean_eurepoc_value(row.get("initiator_category")),
            actor_name,
        ),
        "attribution_status": _map_attribution_status(
            row.get("attribution_type"),
            row.get("settled_initiator"),
            actor_name,
        ),
        "vuln_status": _derive_vuln_status(
            zero_days_value,
            mitre_initial_access,
        ),
        "primary_cve_id": None,
        "zero_day_flag": _derive_zero_day_flag(zero_days_value),
        "is_high_impact": _derive_is_high_impact(
            row.get("weighted_intensity"),
            row.get("impact_indicator_score"),
            row.get("has_disruption"),
            row.get("data_theft"),
        ),
        "geography_type": "country" if country else ("region" if region else None),
        "region": region,
        "country": country,
        "city": None,
        "latitude": None,
        "longitude": None,
        "source_count": 0,
        "high_credibility_source_count": 0,
        "summary_short": _clean_summary(row.get("description")),
        "summary_medium": None,
        "tags": {
            "source_dataset": "EuRepoC",
            "incident_id": row.get("incident_id"),
            "receiver_category": row.get("receiver_category"),
            "receiver_subcategory": row.get("receiver_subcategory"),
            "incident_type": row.get("incident_type"),
            "source_url": row.get("source_url"),
        },
    }

    return _postprocess_mapped_event(event)

def load_eurepoc_global_dataset(filepath=None):
    if filepath is None:
        filepath = Path(__file__).resolve().parents[1] / "data" / "eurepoc_global_dataset_1_3.csv"

    records = []

    with open(filepath, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(map_eurepoc_row_to_cyber_event(row))

    return records