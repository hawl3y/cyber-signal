from datetime import datetime
from pathlib import Path
import json
import re

from app.extensions import db
from app.models import CyberEvent


def _parse_datetime(value):
    if not value:
        return None

    if isinstance(value, datetime):
        return value

    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

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


def _slugify(value):
    if not value:
        return "unknown"

    slug = value.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")

    return slug or "unknown"


def _build_historical_slug(record):
    victim_org_name = record.get("victim_org_name")
    victim_org_normalized = (
        record.get("victim_org_normalized")
        or _normalize_org_name(victim_org_name)
        or "unknown-org"
    )

    attack_type = record.get("attack_type") or "unknown-attack"
    geography = record.get("country") or record.get("region") or "unknown-geo"

    occurred_at = _parse_datetime(record.get("event_occurred_at"))
    year = str(occurred_at.year) if occurred_at else "unknown-year"

    return "hist-{org}-{attack}-{geo}-{year}".format(
        org=_slugify(victim_org_normalized),
        attack=_slugify(attack_type),
        geo=_slugify(geography),
        year=year,
    )


def load_historical_seed_records():
    seed_path = Path(__file__).resolve().parents[1] / "data" / "historical_events_seed.json"

    if not seed_path.exists():
        return []

    with seed_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    return data if isinstance(data, list) else []


def ingest_historical_events_job(records):
    created = 0
    updated = 0

    for record in records:
        victim_org_name = record.get("victim_org_name")
        victim_org_normalized = (
            record.get("victim_org_normalized")
            or _normalize_org_name(victim_org_name)
        )

        slug = record.get("slug") or _build_historical_slug(
            {
                **record,
                "victim_org_normalized": victim_org_normalized,
            }
        )

        event = CyberEvent.query.filter_by(slug=slug).first()

        if event is None:
            event = CyberEvent(slug=slug)
            db.session.add(event)
            created += 1
        else:
            updated += 1

        event.canonical_title = record.get("canonical_title") or "Untitled Historical Event"
        event.event_status = record.get("event_status") or "historical"
        event.verification_level = record.get("verification_level") or "high"
        event.record_origin = record.get("record_origin") or "historical_dataset"

        event.confidence_level = record.get("confidence_level") or "high"
        event.confidence_score = record.get("confidence_score")

        event.first_seen_at = _parse_datetime(record.get("first_seen_at"))
        event.last_seen_at = _parse_datetime(record.get("last_seen_at"))
        event.event_occurred_at = _parse_datetime(record.get("event_occurred_at"))

        event.victim_org_name = victim_org_name
        event.victim_org_normalized = victim_org_normalized
        event.industry = record.get("industry")

        event.attack_type = record.get("attack_type")
        event.access_vector = record.get("access_vector")
        event.impact_type = record.get("impact_type")

        event.actor_name = record.get("actor_name")
        event.actor_type = record.get("actor_type")
        event.attribution_status = record.get("attribution_status") or "unattributed"

        event.vuln_status = record.get("vuln_status")
        event.primary_cve_id = record.get("primary_cve_id")
        event.zero_day_flag = record.get("zero_day_flag", False)
        event.is_high_impact = record.get("is_high_impact", False)

        event.geography_type = record.get("geography_type")
        event.region = record.get("region")
        event.country = record.get("country")
        event.city = record.get("city")
        event.latitude = record.get("latitude")
        event.longitude = record.get("longitude")

        event.source_count = record.get("source_count", 0)
        event.high_credibility_source_count = record.get("high_credibility_source_count", 0)

        event.summary_short = record.get("summary_short")
        event.summary_medium = record.get("summary_medium")
        event.tags = record.get("tags")

        event.last_enriched_at = datetime.utcnow()
        event.last_confidence_scored_at = datetime.utcnow()

    db.session.commit()

    return {
        "created": created,
        "updated": updated,
        "total": created + updated,
    }