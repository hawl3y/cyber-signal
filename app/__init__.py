from dotenv import load_dotenv
load_dotenv()

from flask import Flask
from config import Config
from app.extensions import db, migrate
from app.blueprints.events import events_bp
from app.blueprints.summary import summary_bp
from app.blueprints.filters import filters_bp
from app.blueprints.ingestion import ingestion_bp
from app.blueprints.processing import processing_bp
from app.blueprints.extraction import extraction_bp
from app.blueprints.clustering import clustering_bp
from app.blueprints.enrichment import enrichment_bp
from app.blueprints.scoring import scoring_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)

    from app import models

    app.register_blueprint(events_bp)
    app.register_blueprint(summary_bp)
    app.register_blueprint(filters_bp)
    app.register_blueprint(ingestion_bp)
    app.register_blueprint(processing_bp)
    app.register_blueprint(extraction_bp)
    app.register_blueprint(clustering_bp)
    app.register_blueprint(enrichment_bp)
    app.register_blueprint(scoring_bp)

    @app.route("/")
    def home():
        return {"status": "ok"}

    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Not found"}, 404

    @app.errorhandler(500)
    def server_error(error):
        return {"error": "Internal server error"}, 500

    return app