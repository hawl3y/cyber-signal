from datetime import datetime

from app.extensions import db


class EventSourceLink(db.Model):
    __tablename__ = "event_source_links"

    id = db.Column(db.Integer, primary_key=True)

    cyber_event_id = db.Column(
        db.Integer,
        db.ForeignKey("cyber_events.id"),
        nullable=False,
    )

    raw_article_id = db.Column(
        db.Integer,
        db.ForeignKey("raw_articles.id"),
        nullable=False,
    )

    match_score = db.Column(db.Float)
    is_primary_source = db.Column(db.Boolean, default=False)
    linked_at = db.Column(db.DateTime, default=datetime.utcnow)

    cyber_event = db.relationship(
    "CyberEvent",
    back_populates="event_sources")