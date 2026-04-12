from dotenv import load_dotenv
load_dotenv()

from flask import Flask
from config import Config
from app.extensions import db, migrate
from app.blueprints.events import events_bp
from app.blueprints.summary import summary_bp
from app.blueprints.filters import filters_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)

    from app import models

    app.register_blueprint(events_bp)
    app.register_blueprint(summary_bp)
    app.register_blueprint(filters_bp)

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