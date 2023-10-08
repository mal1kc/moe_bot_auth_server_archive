import logging

from flask import Flask

from . import paths
from .admin_control import admin_control_blueprint
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

LOGGER = logging.getLogger("app")


def _ensure_secret_key(app) -> None:
    if app.config["SECRET_KEY"] is None:
        LOGGER.debug("Generating secret key")
        app.config["SECRET_KEY"] = conf_secret_key.generate_secret_key()
        LOGGER.debug("Secret key generated")


def _ensure_db(app) -> None:
    """Ensure that a database exists."""
    LOGGER.debug("Ensuring database url %s", app.config["SQLALCHEMY_DATABASE_URI"])
    db.create_all()


def create_app() -> Flask:
    app = Flask("moe_bot_auth_server")
    register_modifications(app)
    register_folders(app)
    _ensure_secret_key(app)
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
    app_config = conf_flask.Config.from_toml(paths.CONFIG_FILE_PATH)
    app.config.from_object(app_config)
    LOGGER.debug("config loaded")
    LOGGER.debug("config -> {}".format(app.config))


def register_folders(app: Flask) -> None:
    LOGGER.debug("Registering folders")
    # print("static folder ->",app.config["STATIC_FOLDER"])
    # print("template folder ->",app.config["TEMPLATE_FOLDER"])
    app.static_folder = app.config["STATIC_FOLDER"]
    app.template_folder = app.config["TEMPLATE_FOLDER"]
    # print("static folder ->",app.static_folder)
    # print("template folder ->",app.template_folder)
    LOGGER.debug("Folders registered")
