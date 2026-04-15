from datetime import datetime

from app.extensions import db


class ArticleExtraction(db.Model):
    __tablename__ = "article_extractions"

    id = db.Column(db.Integer, primary_key=True)

    raw_article_id = db.Column(
        db.Integer,
        db.ForeignKey("raw_articles.id"),
        nullable=False,
    )

    victim_org_name = db.Column(db.String(255))
    victim_org_normalized = db.Column(db.String(255))
    victim_entity_type = db.Column(db.String(100))
    victim_display_label = db.Column(db.String(255))
    industry = db.Column(db.String(100))
    region = db.Column(db.String(100))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))

    attack_type = db.Column(db.String(100))
    access_vector = db.Column(db.String(100))
    impact_type = db.Column(db.String(100))

    actor_name = db.Column(db.String(255))
    actor_type = db.Column(db.String(100))
    attribution_status = db.Column(db.String(100))

    vuln_status = db.Column(db.String(100))
    cve_ids = db.Column(db.JSON)
    zero_day_flag = db.Column(db.Boolean, default=False)

    short_event_summary = db.Column(db.Text)
    extracted_signals = db.Column(db.JSON)
    extraction_confidence = db.Column(db.Float)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    raw_article = db.relationship(
    "RawArticle",
    back_populates="extractions")