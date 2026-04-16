from app.services.taxonomy import (
    fallback_industry_from_entity_type,
    normalize_entity_type,
    normalize_industry,
)


def resolve_classification_from_org_lookup(org_lookup_result):
    if not org_lookup_result:
        return {
            "victim_entity_type": "unknown",
            "industry": "Other",
            "source": "org_lookup_missing",
        }

    entity_type = normalize_entity_type(org_lookup_result.get("victim_entity_type"))
    industry = normalize_industry(org_lookup_result.get("industry"))

    if industry == "Other" and entity_type != "unknown":
        industry = fallback_industry_from_entity_type(entity_type)

    return {
        "victim_entity_type": entity_type,
        "industry": industry,
        "source": org_lookup_result.get("source", "org_lookup"),
    }


def resolve_classification_from_industry(industry_value, source="industry"):
    industry = normalize_industry(industry_value)

    industry_entity_map = {
        "Government": "government",
        "Financial Services": "private_sector",
        "Transportation": "critical_infrastructure",
        "Healthcare": "private_sector",
        "Education": "private_sector",
        "Technology": "private_sector",
        "Energy": "critical_infrastructure",
        "Media": "private_sector",
        "Private Sector": "private_sector",
        "Other": "unknown",
    }

    entity_type = normalize_entity_type(industry_entity_map.get(industry))

    return {
        "victim_entity_type": entity_type,
        "industry": industry,
        "source": source,
    }


def resolve_classification(org_lookup_result=None, industry_value=None, source_prefix="classification"):
    if org_lookup_result:
        resolved = resolve_classification_from_org_lookup(org_lookup_result)
        if resolved["victim_entity_type"] != "unknown" or resolved["industry"] != "Other":
            return {
                "victim_entity_type": resolved["victim_entity_type"],
                "industry": resolved["industry"],
                "source": f"{source_prefix}_org",
            }

    if industry_value is not None:
        resolved = resolve_classification_from_industry(
            industry_value,
            source=f"{source_prefix}_industry",
        )
        if resolved["industry"] != "Other" or resolved["victim_entity_type"] != "unknown":
            return resolved

    return {
        "victim_entity_type": "unknown",
        "industry": "Other",
        "source": f"{source_prefix}_fallback",
    }