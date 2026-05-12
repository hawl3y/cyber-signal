from app import create_app
from app.extensions import db
from app.models import EventSourceLink, ArticleExtraction, CyberEvent, RawArticle

app = create_app()
with app.app_context():
    EventSourceLink.query.delete()
    ArticleExtraction.query.delete()
    CyberEvent.query.delete()
    RawArticle.query.delete()
    db.session.commit()
    print("content reset complete.")
