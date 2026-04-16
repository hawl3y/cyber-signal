ENTITY_TYPES = {
    "government",
    "private_sector",
    "critical_infrastructure",
    "individuals",
    "civil_society",
    "international",
    "unknown",
}

INDUSTRIES = {
    "Government",
    "Financial Services",
    "Transportation",
    "Healthcare",
    "Education",
    "Technology",
    "Energy",
    "Media",
    "Private Sector",
    "Other",
}

ATTACK_TYPES = {
    "Ransomware",
    "Data Breach",
    "DDoS",
    "Malware",
    "Exploitation",
    "Account Compromise",
    "Phishing",
    "Disruption",
    "Unknown",
}

ACCESS_VECTORS = {
    "Phishing",
    "Exploitation",
    "Credential Abuse",
    "Third-Party",
    "Remote Access",
    "Email",
    "Web",
    "Network Device",
    "Unknown Initial Access",
    "Unknown",
}

IMPACT_TYPES = {
    "Data Theft",
    "Operational Disruption",
    "Extortion",
    "Financial Loss",
    "Account Compromise",
    "Unknown",
}

ACTOR_TYPES = {
    "State Actor",
    "Threat Group",
    "Cybercrime Group",
    "Hacktivist",
    "Unknown",
}

ATTRIBUTION_STATUSES = {
    "attributed",
    "claimed",
    "unattributed",
}

VULN_STATUSES = {
    "known_vulnerability",
    "unknown",
}

EVENT_STATUSES = {
    "candidate",
    "open",
    "confirmed",
    "historical",
    "hybrid",
}

VERIFICATION_LEVELS = {
    "low",
    "medium",
    "high",
}

RECORD_ORIGINS = {
    "live_detection",
    "historical_dataset",
    "hybrid",
}

ENTITY_TYPE_TO_INDUSTRY = {
    "government": "Government",
    "private_sector": "Other",
    "critical_infrastructure": "Other",
    "individuals": "Other",
    "civil_society": "Other",
    "international": "Other",
    "unknown": "Other",
}

LEGACY_ENTITY_TYPE_MAP = {
    "government": "government",
    "political": "government",
    "military": "government",
    "financial": "private_sector",
    "transportation": "private_sector",
    "healthcare": "private_sector",
    "education": "private_sector",
    "media": "private_sector",
    "technology": "private_sector",
    "research": "private_sector",
    "private_sector": "private_sector",
    "critical_infrastructure": "critical_infrastructure",
    "civil_society": "civil_society",
    "international": "international",
    "individuals": "individuals",
    "unknown": "unknown",
    None: "unknown",
}

LEGACY_INDUSTRY_MAP = {
    "Government": "Government",
    "Financial Services": "Financial Services",
    "Transportation": "Transportation",
    "Healthcare": "Healthcare",
    "Education": "Education",
    "Technology": "Technology",
    "Energy": "Energy",
    "Media": "Media",
    "Private Sector": "Private Sector",
    "Other": "Other",
    "Consumer Services": "Private Sector",
    "Retail": "Private Sector",
    "Manufacturing": "Private Sector",
    "Telecommunications": "Technology",
    None: "Other",
}

LEGACY_ATTACK_TYPE_MAP = {
    "Ransomware": "Ransomware",
    "Data Breach": "Data Breach",
    "DDoS": "DDoS",
    "Malware": "Malware",
    "Exploitation": "Exploitation",
    "Account Compromise": "Account Compromise",
    "Phishing": "Phishing",
    "Disruption": "Disruption",
    "Unknown": "Unknown",
    None: "Unknown",
}

LEGACY_ACCESS_VECTOR_MAP = {
    "Phishing": "Phishing",
    "Exploitation": "Exploitation",
    "Credential Abuse": "Credential Abuse",
    "Third-Party": "Third-Party",
    "Remote Access": "Remote Access",
    "Email": "Email",
    "Web": "Web",
    "Network Device": "Network Device",
    "Unknown Initial Access": "Unknown Initial Access",
    "Unknown": "Unknown",
    None: "Unknown",
}

LEGACY_IMPACT_TYPE_MAP = {
    "Data Theft": "Data Theft",
    "Operational Disruption": "Operational Disruption",
    "Extortion": "Extortion",
    "Financial Loss": "Financial Loss",
    "Account Compromise": "Account Compromise",
    None: "Unknown",
}

LEGACY_ACTOR_TYPE_MAP = {
    "State Actor": "State Actor",
    "Threat Group": "Threat Group",
    "Cybercrime Group": "Cybercrime Group",
    "Hacktivist": "Hacktivist",
    None: "Unknown",
}

LEGACY_ATTRIBUTION_STATUS_MAP = {
    "attributed": "attributed",
    "claimed": "claimed",
    "unattributed": "unattributed",
    None: "unattributed",
}

LEGACY_VULN_STATUS_MAP = {
    "known_vulnerability": "known_vulnerability",
    "unknown": "unknown",
    None: "unknown",
}

LEGACY_EVENT_STATUS_MAP = {
    "candidate": "candidate",
    "open": "open",
    "confirmed": "confirmed",
    "historical": "historical",
    "hybrid": "hybrid",
    None: "candidate",
}

LEGACY_VERIFICATION_LEVEL_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    None: "low",
}

LEGACY_RECORD_ORIGIN_MAP = {
    "live_detection": "live_detection",
    "historical_dataset": "historical_dataset",
    "hybrid": "hybrid",
    None: "live_detection",
}


def _normalize_from_map(value, value_map, allowed_values, default):
    normalized = value_map.get(value, default)
    if normalized not in allowed_values:
        return default
    return normalized


def normalize_entity_type(value):
    return _normalize_from_map(
        value,
        LEGACY_ENTITY_TYPE_MAP,
        ENTITY_TYPES,
        "unknown",
    )


def normalize_industry(value):
    return _normalize_from_map(
        value,
        LEGACY_INDUSTRY_MAP,
        INDUSTRIES,
        "Other",
    )


def normalize_attack_type(value):
    return _normalize_from_map(
        value,
        LEGACY_ATTACK_TYPE_MAP,
        ATTACK_TYPES,
        "Unknown",
    )


def normalize_access_vector(value):
    return _normalize_from_map(
        value,
        LEGACY_ACCESS_VECTOR_MAP,
        ACCESS_VECTORS,
        "Unknown",
    )


def normalize_impact_type(value):
    return _normalize_from_map(
        value,
        LEGACY_IMPACT_TYPE_MAP,
        IMPACT_TYPES,
        "Unknown",
    )


def normalize_actor_type(value):
    return _normalize_from_map(
        value,
        LEGACY_ACTOR_TYPE_MAP,
        ACTOR_TYPES,
        "Unknown",
    )


def normalize_attribution_status(value):
    return _normalize_from_map(
        value,
        LEGACY_ATTRIBUTION_STATUS_MAP,
        ATTRIBUTION_STATUSES,
        "unattributed",
    )


def normalize_vuln_status(value):
    return _normalize_from_map(
        value,
        LEGACY_VULN_STATUS_MAP,
        VULN_STATUSES,
        "unknown",
    )


def normalize_event_status(value):
    return _normalize_from_map(
        value,
        LEGACY_EVENT_STATUS_MAP,
        EVENT_STATUSES,
        "candidate",
    )


def normalize_verification_level(value):
    return _normalize_from_map(
        value,
        LEGACY_VERIFICATION_LEVEL_MAP,
        VERIFICATION_LEVELS,
        "low",
    )


def normalize_record_origin(value):
    return _normalize_from_map(
        value,
        LEGACY_RECORD_ORIGIN_MAP,
        RECORD_ORIGINS,
        "live_detection",
    )


def fallback_industry_from_entity_type(entity_type):
    normalized_entity_type = normalize_entity_type(entity_type)
    return ENTITY_TYPE_TO_INDUSTRY.get(normalized_entity_type, "Other")