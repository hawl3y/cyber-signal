from datetime import datetime

from app.extensions import db


class AutomationRun(db.Model):
    __tablename__ = "automation_runs"

    id = db.Column(db.Integer, primary_key=True)

    started_at = db.Column(db.DateTime, nullable=False)
    finished_at = db.Column(db.DateTime)
    success = db.Column(db.Boolean)
    result = db.Column(db.JSON)
    error = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)