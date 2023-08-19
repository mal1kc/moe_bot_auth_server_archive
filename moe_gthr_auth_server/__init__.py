import os

from flask import Flask

from . import paths
from .config import flask as conf_flask
from .config import secret_key as conf_secret_key
from .database_ops import db
from .err_handlrs import bad_request, error_blueprint, not_found, unauthorized, unsupported_media_type
from .main_app import main_blueprint


def _ensure_secret_key() -> None:
    """Ensure that a secret key exists."""
    if os.path.exists(paths.SECRET_KEY_PATH):
        return
    conf_secret_key.write(conf_secret_key.generate_secret_key())


def create_app() -> Flask:
    app = Flask("moe_gatherer_server")
    _ensure_secret_key()
    register_modifications(app)
    register_extensions(app)
    register_blueprints(app)
    return app


def register_blueprints(app: Flask) -> None:
    app.register_blueprint(error_blueprint)
    app.register_blueprint(main_blueprint)


def register_extensions(app: Flask, db=db) -> None:
    db.init_app(app)


def register_error_handlers(app: Flask):
    app.register_error_handler(400, bad_request)
    app.register_error_handler(401, unauthorized)
    app.register_error_handler(404, not_found)
    app.register_error_handler(415, unsupported_media_type)


def register_modifications(app: Flask) -> None:
    app.config.from_object(conf_flask)
    app.secret_key = conf_secret_key.read()
