import os

from .config import flask as conf_flask
from .config import secret_key as conf_secret_key
from flask import Flask

from . import paths
from .database_ops import db
from .routes import main_blueprint


def _ensure_secret_key() -> None:
    """Ensure that a secret key exists."""
    if os.path.exists(paths.SECRET_KEY_PATH):
        return
    conf_secret_key.write(conf_secret_key.generate_secret_key())


def create() -> Flask:
    app = Flask("moe_gatherer_server")
    register_modifications(app)
    register_extensions(app)
    register_blueprints(app)
    return app


def register_blueprints(app: Flask) -> None:
    app.register_blueprint(main_blueprint)


def register_extensions(app: Flask, db=db) -> None:
    db.init_app(app)


def register_modifications(app: Flask) -> None:
    app.config.from_object(conf_flask)
    app.secret_key = conf_secret_key.read()
