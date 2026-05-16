# Threat type taxonomy grounded in the VERIS framework (veriscommunity.net)
# and DBIR incident patterns from the Verizon Data Breach Investigations Report.
#
# Each type maps to a primary VERIS action category and the closest DBIR pattern.
# Detection order in extraction.py runs most-specific first; Exploitation is the
# VERIS Hacking catch-all and fires on any confirmed intrusion that doesn't fit
# a more specific label.
#
# VERIS action categories: Hacking, Malware, Social, Misuse, Physical, Error, Environmental
# DBIR patterns: Ransomware, System Intrusion, Social Engineering, Basic Web Application
#   Attacks, Denial of Service, Lost and Stolen Assets, Privilege Misuse, Crimeware,
#   Cyber-Espionage, Miscellaneous Errors, Everything Else
#
# Activity-only types (pipeline-internal, never shown in the incident feed):
#   Authentication Bypass, Remote Code Execution, Privilege Escalation, Injection
#   — these are CISA advisory vulnerability classes, not incident delivery methods.

ATTACK_TYPES = {
    # VERIS: Hacking | DBIR: System Intrusion
    # Compromised software dependency, vendor update, or third-party component.
    "Supply Chain",

    # VERIS: Malware (ransomware variety) | DBIR: Ransomware
    # Encryption of victim systems combined with extortion demand.
    "Ransomware",

    # VERIS: Hacking | DBIR: System Intrusion (financial motivation)
    # Funds, cryptocurrency, or other monetary assets stolen from financial systems
    # or protocols. Covers DeFi exploits, crypto heists, wire fraud, flash loan attacks.
    # Distinct from Data Breach (no personal data angle) and Exploitation (labels outcome
    # rather than mechanism when the primary impact is monetary loss).
    "Financial Theft",

    # VERIS: Hacking (DoS variety) | DBIR: Denial of Service
    # Volumetric or application-layer attack degrading availability.
    "DDoS",

    # VERIS: Social | DBIR: Social Engineering
    # Deceptive communication (email, SMS, voice) used to obtain credentials or access.
    "Phishing",

    # VERIS: Hacking + Exfiltrate result | DBIR: System Intrusion / Basic Web App
    # Unauthorized access resulting in data exfiltrated or exposed.
    "Data Breach",

    # VERIS: Hacking (stolen creds) / Misuse | DBIR: Privilege Misuse
    # Existing credentials abused to gain unauthorized account access.
    "Account Compromise",

    # VERIS: Malware (non-ransomware varieties) | DBIR: Crimeware / System Intrusion
    # Malicious code deployed: trojans, backdoors, wipers, infostealers, spyware.
    "Malware",

    # VERIS: Hacking | DBIR: Basic Web Application Attacks / System Intrusion
    # Technical vulnerability exploited. Also the catch-all for any confirmed intrusion
    # (hacked, cyberattack, unauthorized access) where no more specific type applies.
    "Exploitation",

    # VERIS: Any action | DBIR: Everything Else
    # Availability impact confirmed but attack mechanism not identified in article text.
    "Disruption",

    # Pipeline-internal types — CISA advisory vulnerability classes, never shown in feed.
    "Authentication Bypass",   # VERIS: Hacking/Bypass
    "Remote Code Execution",   # VERIS: Hacking/RCE
    "Privilege Escalation",    # VERIS: Hacking/Privilege Abuse
    "Injection",               # VERIS: Hacking/Injection

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
    "Financial Theft": "Financial Theft",
    "Disruption": "Disruption",
    "Authentication Bypass": "Authentication Bypass",
    "Remote Code Execution": "Remote Code Execution",
    "Privilege Escalation": "Privilege Escalation",
    "Injection": "Injection",
    "Supply Chain": "Supply Chain",
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


EVENT_ANCHOR_TYPES = {
    "organization",
    "product_or_platform",
    "vulnerability",
    "campaign",
    "actor",
    "unknown",
}


def normalize_event_anchor_type(value):
    if value in EVENT_ANCHOR_TYPES:
        return value
    return "unknown"