from datetime import datetime

from app.extensions import db


class EnrichmentAuditLog(db.Model):
    """
    Per-event AI enrichment call audit. Captures the inputs (event state
    before the call), the AI return payloads, the merged result, and the
    cost (tokens, duration). Used to answer: which fields is the AI
    actually filling, and is it worth the spend?
    """

    __tablename__ = "enrichment_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, nullable=False, index=True)

    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    duration_ms = db.Column(db.Integer)

    article_called = db.Column(db.Boolean, default=False)
    web_called = db.Column(db.Boolean, default=False)

    fields_before = db.Column(db.JSON)
    fields_after = db.Column(db.JSON)
    article_returned = db.Column(db.JSON)
    web_returned = db.Column(db.JSON)

    fields_filled = db.Column(db.JSON)

    article_usage = db.Column(db.JSON)
    web_usage = db.Column(db.JSON)

    error = db.Column(db.String(500))

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
