from datetime import datetime

from app.extensions import db


class SourceReputation(db.Model):
    __tablename__ = "source_reputations"

    id = db.Column(db.Integer, primary_key=True)

    source_name = db.Column(db.String(255), unique=True, nullable=False)
    reputation_tier = db.Column(db.String(50))
    reputation_score = db.Column(db.Float)
    source_category = db.Column(db.String(100))

    active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)