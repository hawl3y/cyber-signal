from app.extensions import db


class EventCVELink(db.Model):
    __tablename__ = "event_cve_links"

    id = db.Column(db.Integer, primary_key=True)

    cyber_event_id = db.Column(
        db.Integer,
        db.ForeignKey("cyber_events.id"),
        nullable=False,
    )

    cve_id = db.Column(db.String(50), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)

    cyber_event = db.relationship(
    "CyberEvent",
    back_populates="event_cves")