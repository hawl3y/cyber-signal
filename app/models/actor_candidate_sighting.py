from datetime import datetime

from app.extensions import db


class ActorCandidateSighting(db.Model):
    """
    A capitalized phrase observed in an article near attribution language
    that did not match any name or alias in the curated THREAT_ACTORS list
    when the audit ran. Persisted so the curator can review accumulated
    candidates and decide which to add to the curated list.

    Unique per (candidate_name, raw_article_id) — re-running the audit
    job over the same article does not duplicate.
    """

    __tablename__ = "actor_candidate_sightings"

    id = db.Column(db.Integer, primary_key=True)
    candidate_name = db.Column(db.String(160), nullable=False, index=True)
    raw_article_id = db.Column(
        db.Integer,
        db.ForeignKey("raw_articles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    seen_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    context_snippet = db.Column(db.Text)

    __table_args__ = (
        db.UniqueConstraint(
            "candidate_name",
            "raw_article_id",
            name="uq_actor_candidate_sighting",
        ),
    )
