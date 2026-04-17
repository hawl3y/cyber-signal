from datetime import datetime

from app.extensions import db


class CyberEvent(db.Model):
    __tablename__ = "cyber_events"

    id = db.Column(db.Integer, primary_key=True)

    canonical_title = db.Column(db.String(500), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False)

    event_status = db.Column(db.String(50), default="emerging")
    verification_level = db.Column(db.String(50))
    record_origin = db.Column(db.String(50))

    confidence_level = db.Column(db.String(50))
    confidence_score = db.Column(db.Float)

    first_seen_at = db.Column(db.DateTime)
    last_seen_at = db.Column(db.DateTime)
    event_occurred_at = db.Column(db.DateTime)

    victim_org_name = db.Column(db.String(255))
    victim_org_normalized = db.Column(db.String(255))
    victim_entity_type = db.Column(db.String(100))
    victim_display_label = db.Column(db.String(255))
    industry = db.Column(db.String(100))

    attack_type = db.Column(db.String(100))
    access_vector = db.Column(db.String(100))
    impact_type = db.Column(db.String(100))

    actor_name = db.Column(db.String(255))
    actor_type = db.Column(db.String(100))
    attribution_status = db.Column(db.String(100))

    vuln_status = db.Column(db.String(100))
    primary_cve_id = db.Column(db.String(50))
    zero_day_flag = db.Column(db.Boolean, default=False)
    is_high_impact = db.Column(db.Boolean, default=False)

    geography_type = db.Column(db.String(50))
    region = db.Column(db.String(100))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

    source_count = db.Column(db.Integer, default=0)
    high_credibility_source_count = db.Column(db.Integer, default=0)

    event_cluster_key = db.Column(db.String(255))

    last_confidence_scored_at = db.Column(db.DateTime)
    last_enriched_at = db.Column(db.DateTime)

    summary_short = db.Column(db.Text)
    summary_medium = db.Column(db.Text)
    tags = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    event_sources = db.relationship(
    "EventSourceLink",
    back_populates="cyber_event",
    lazy=True)