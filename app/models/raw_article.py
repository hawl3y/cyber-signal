from datetime import datetime

from app.extensions import db

class RawArticle(db.Model):
    __tablename__ = "raw_articles"

    id = db.Column(db.Integer, primary_key=True)

    source_type = db.Column(db.String(50))
    source_name = db.Column(db.String(255))
    source_url = db.Column(db.Text)
    publisher = db.Column(db.String(255))

    article_url = db.Column(db.Text, unique=True, nullable=False)

    title = db.Column(db.Text)
    normalized_title = db.Column(db.Text)
    summary = db.Column(db.Text)
    content = db.Column(db.Text)

    normalized_domain = db.Column(db.String(255))

    ingestion_batch_id = db.Column(db.String(100))

    published_at = db.Column(db.DateTime)
    fetched_at = db.Column(db.DateTime)

    content_hash = db.Column(db.String(64))
    title_hash = db.Column(db.String(64))

    language = db.Column(db.String(10))

    is_duplicate = db.Column(db.Boolean, default=False)
    duplicate_of_article_id = db.Column(db.Integer)

    processing_status = db.Column(db.String(50))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    event_links = db.relationship(
    "EventSourceLink",
    backref="raw_article",
    lazy=True)

    extractions = db.relationship(
    "ArticleExtraction",
    back_populates="raw_article",
    lazy=True)