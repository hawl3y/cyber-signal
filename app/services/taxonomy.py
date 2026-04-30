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


def _normalize_from_map(value, value_map, allowed_values, default):
    normalized = value_map.get(value, default)
    if normalized not in allowed_values:
        return default
    return normalized


def normalize_attack_type(value):
    return _normalize_from_map(
        value,
        LEGACY_ATTACK_TYPE_MAP,
        ATTACK_TYPES,
        "Unknown",
    )