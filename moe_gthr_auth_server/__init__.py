import logging
import os

from flask import Flask

from . import paths
from .cli import cli_blueprint
from .config import flask as conf_flask
from .config import secret_key as conf_secret_key
from .database_ops import db
from .err_handlrs import (
    bad_request,
    error_blueprint,
    method_not_allowed,
    not_found,
    unauthorized,
    unsupported_media_type,
)
from .main_app import main_blueprint
from .admin_control import admin_control_blueprint

LOGGER = logging.getLogger("app")


def _ensure_secret_key() -> None:
    """Ensure that a secret key exists."""
    LOGGER.debug("Ensuring secret key file %s", paths.SECRET_KEY_PATH)
    if os.path.exists(paths.SECRET_KEY_PATH):
        return
    conf_secret_key.write(conf_secret_key.generate_random_bytes())


def _ensure_db(app) -> None:
    """Ensure that a database exists."""
    LOGGER.debug(
        "Ensuring database file %s", app.config["SQLALCHEMY_DATABASE_URI"].split("///")[1]
    )
    if os.path.exists(app.config["SQLALCHEMY_DATABASE_URI"].split("///")[1]):
        return
    db.create_all()


def create_app() -> Flask:
    app = Flask("moe_gatherer_server")
    _ensure_secret_key()
    register_modifications(app)
    register_extensions(app)
    register_blueprints(app)
    register_error_handlers(app)
    return app


def register_blueprints(app: Flask) -> None:
    LOGGER.debug("Registering blueprints")
    app.register_blueprint(error_blueprint)
    app.register_blueprint(main_blueprint)
    app.register_blueprint(cli_blueprint)
    app.register_blueprint(admin_control_blueprint)


def register_extensions(app: Flask, db=db) -> None:
    db.init_app(app)
    print(
        "app.config['SQLALCHEMY_DATABASE_URI'] -> {}".format(
            app.config["SQLALCHEMY_DATABASE_URI"]
        )
    )
    with app.app_context():
        _ensure_db(app)


def register_error_handlers(app: Flask):
    LOGGER.debug("Registering error handlers")
    app.register_error_handler(400, bad_request)
    app.register_error_handler(401, unauthorized)
    app.register_error_handler(404, not_found)
    app.register_error_handler(415, unsupported_media_type)
    app.register_error_handler(405, method_not_allowed)


def register_modifications(app: Flask) -> None:
    LOGGER.debug("Registering modifications")
    app.config.from_object(conf_flask.load_config_from_toml())
    LOGGER.debug("config loaded")
    LOGGER.debug("config -> {}".format(app.config))
    # app.secret_key = conf_secret_key.read()
