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
    value = _pick_first_meaningful_semicolon_value(value)
    if not value:
        return None

    lowered = value.lower()

    if "state institutions" in lowered or "political system" in lowered or "government" in lowered:
        return "public_sector"

    if "critical infrastructure" in lowered:
        return "critical_infrastructure"

    if "corporate" in lowered or "private sector" in lowered or "company" in lowered or "business" in lowered:
        return "private_sector"

    if "media" in lowered or "journalism" in lowered or "news" in lowered or "newspaper" in lowered:
        return "media"

    if "social groups" in lowered or "activists" in lowered or "advocacy" in lowered or "human rights" in lowered:
        return "civil_society"

    if "international" in lowered or "supranational" in lowered or "humanitarian" in lowered:
        return "international"

    if "end user" in lowered or "specially protected groups" in lowered or "individual" in lowered:
        return "individuals"

    if "science" in lowered or "research" in lowered:
        return "research"

    if "health" in lowered or "hospital" in lowered or "medical" in lowered:
        return "healthcare"

    if "education" in lowered or "university" in lowered or "school" in lowered:
        return "education"

    return None


def _simplify_receiver_subcategory(value):
    value = _pick_first_meaningful_semicolon_value(value)
    value = _clean_eurepoc_value(value)
    if not value:
        return None

    value = re.sub(r"\s*\(e\.g\.[^)]+\)", "", value, flags=re.IGNORECASE)
    value = re.sub(r"\s+", " ", value).strip()

    lowered = value.lower()

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
    }

    if lowered in generic_map:
        return generic_map[lowered]

    return value


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

def _derive_victim_label(receiver_name, receiver_category, receiver_subcategory, receiver_country):
    name = _pick_first_meaningful_semicolon_value(receiver_name)
    if name:
        return name

    subcategory = _simplify_receiver_subcategory(receiver_subcategory)
    if subcategory:
        country = _pick_first_meaningful_semicolon_value(receiver_country)
        return f"{subcategory} ({country})" if country else subcategory

    category_family = _simplify_receiver_category(receiver_category)
    if category_family:
        return _build_target_fallback_label(
            category_family,
            None,
            _pick_first_meaningful_semicolon_value(receiver_country),
        )

    # LAST RESORT ONLY
    return _build_target_fallback_label(
        None,
        None,
        _pick_first_meaningful_semicolon_value(receiver_country),
    )


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


def _map_industry(receiver_category, receiver_subcategory):
    text = " ".join(
        [
            receiver_category or "",
            receiver_subcategory or "",
        ]
    ).lower()

    if any(term in text for term in ["public_sector"]):
        return "Government"

    if any(term in text for term in ["healthcare"]):
        return "Healthcare"

    if any(term in text for term in ["financial"]):
        return "Financial Services"

    if any(term in text for term in ["critical_infrastructure"]):
        return "Energy"

    if any(term in text for term in ["transportation"]):
        return "Transportation"

    if any(term in text for term in ["education"]):
        return "Education"

    if any(term in text for term in ["media"]):
        return "Media"

    if any(term in text for term in ["technology"]):
        return "Technology"

    if any(term in text for term in ["manufacturing"]):
        return "Manufacturing"

    if any(term in text for term in ["private_sector"]):
        return "Private Sector"

    return "Other"


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

    country = event.get("country")

    def with_country(label):
        return f"{label} ({country})" if country else label

    if (
        "state television" in combined
        or "state tv" in combined
        or "television" in combined
        or "broadcaster" in combined
        or "newspaper" in combined
        or "news outlet" in combined
        or "news agency" in combined
    ):
        event["victim_org_name"] = with_country("Media organizations")
        event["industry"] = "Media"

    elif (
        "swift" in combined
        or "bank" in combined
        or "payment system" in combined
        or "financial institution" in combined
    ):
        event["victim_org_name"] = with_country("Financial institutions")
        event["industry"] = "Financial Services"

    elif (
        "airline" in combined
        or "airport" in combined
        or "transport" in combined
        or "rail" in combined
        or "shipping" in combined
    ):
        event["victim_org_name"] = with_country("Transportation organizations")
        event["industry"] = "Transportation"

    elif (
        "westinghouse" in combined
        or "us steel" in combined
        or "lockheed martin" in combined
        or "defense contractor" in combined
        or "electric company" in combined
        or "industrial" in combined
        or "manufacturing" in combined
    ):
        event["victim_org_name"] = with_country("Defense industry organizations")
        event["industry"] = "Technology"

    elif (
        "military" in combined
        or "naval" in combined
        or "air force" in combined
        or "defense ministry" in combined
        or "war college" in combined
        or "centrifuges" in combined
        or "nuclear facility" in combined
        or "niprnet" in combined
    ):
        event["victim_org_name"] = with_country("Military organizations")
        event["industry"] = "Government"

    elif (
        "university" in combined
        or "college" in combined
        or "school" in combined
    ):
        event["victim_org_name"] = with_country("Educational institutions")
        event["industry"] = "Education"

    elif (
        "hospital" in combined
        or "medical center" in combined
        or "healthcare" in combined
    ):
        event["victim_org_name"] = with_country("Healthcare organizations")
        event["industry"] = "Healthcare"

    elif (
        "ministry" in combined
        or "state department" in combined
        or "government" in combined
        or "embassy" in combined
    ):
        event["victim_org_name"] = with_country("Government entities")
        event["industry"] = "Government"

    elif (
        "political party" in combined
        or "political parties" in combined
        or "campaign for president" in combined
        or "election" in combined
    ):
        event["victim_org_name"] = with_country("Political parties")
        event["industry"] = "Government"

    elif (
        "website" in combined
        or "websites" in combined
        or "web site" in combined
        or "web sites" in combined
        or "web host" in combined
        or "internet users" in combined
        or "mobile app" in combined
        or "smartphone" in combined
        or "cyber war" in combined
        or "cyberwar" in combined
        or "defacing web" in combined
    ):
        event["victim_org_name"] = with_country("Technology organizations")
        event["industry"] = "Technology"

    elif (
        "activist" in combined
        or "advocacy" in combined
        or "civil society" in combined
    ):
        event["victim_org_name"] = with_country("Civil society organizations")
        event["industry"] = "Other"

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
    victim_org_name = _derive_victim_label(
        row.get("receiver_name"),
        row.get("receiver_category"),
        row.get("receiver_subcategory"),
        row.get("receiver_country"),
    )
    victim_org_normalized = _normalize_org_name(victim_org_name)

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
        "industry": _map_industry(
            _simplify_receiver_category(row.get("receiver_category")),
            _simplify_receiver_subcategory(row.get("receiver_subcategory")),
        ),
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