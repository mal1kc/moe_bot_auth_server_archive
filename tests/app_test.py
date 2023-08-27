import logging

import pytest
from flask import Flask

from client.encryption import make_password_hash

from moe_gthr_auth_server import register_blueprints, register_error_handlers
from moe_gthr_auth_server.config import endpoints as config_endpoints
from moe_gthr_auth_server.database_ops import (
    Admin,
    add_admin,
    db,
)

from moe_gthr_auth_server.crpytion import (
    compare_encypted_hashes,
    encryption_password,
    simple_dencrypt,
    encoding,
    unmake_password_ready,
)


URLS = config_endpoints._init_urls()

LOGGER = logging.getLogger(__name__)


def make_password_ready(password: str) -> str:
    return simple_dencrypt(make_password_hash(password).encode(encoding), encryption_password).hex()


@pytest.fixture
def app():
    app = Flask("moe_gatherer_server")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    LOGGER.debug("app: %s", app)
    register_blueprints(app)
    register_error_handlers(app)
    db.init_app(app)
    yield app


@pytest.fixture
def app_ctx(app):
    return app.app_context()


@pytest.fixture
def admin_db_data() -> dict:
    return {"name": "ext_test_admin", "password_hash": make_password_hash("ext_test_admin_password")}


@pytest.fixture
def admin_data(admin_db_data) -> dict:
    return {"name": admin_db_data["name"], "password_hash": make_password_ready("ext_test_admin_password")}


@pytest.fixture
def user_db_data() -> dict:
    return {"name": "ext_test_user", "password_hash": make_password_hash("ext_test_user_password")}


@pytest.fixture
def user_data() -> dict:
    return {"name": "ext_test_user", "password_hash": make_password_ready("ext_test_user_password")}


@pytest.fixture(autouse=True)
def init_db(app_ctx, admin_db_data):
    LOGGER.debug("init_db")
    with app_ctx:
        db.create_all()
        db_Admin = Admin(**admin_db_data)
        add_admin(db_Admin)
        yield
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_data_auth(admin_data) -> tuple:
    return (admin_data["name"], admin_data["password_hash"])


def test_cryption(user_data):
    LOGGER.debug("test_cryption")
    assert unmake_password_ready(user_data["password_hash"]) == make_password_hash("ext_test_user_password")
    assert compare_encypted_hashes(user_data["password_hash"], make_password_hash("ext_test_user_password"))
    LOGGER.debug("test_cryption: OK")


def test_can_be_alive(client):
    LOGGER.debug("test_can_be_alive")
    assert client.get("/").status_code == 200
    LOGGER.debug("test_can_be_alive: OK")


@pytest.fixture
def user_data_model_json(user_data) -> dict:
    return {"model_type": "user", "user": {*user_data}}


def test_register_user(client, user_data, admin_data_auth):
    LOGGER.debug("test_register_user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user: OK")


def test_register_unsupported_media(client, admin_data_auth):
    LOGGER.debug("test_register_unsupported_media")
    response = client.post(URLS.ARegister, data="some data", content_type="text/plain", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "unsupported_media_type", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 415
    LOGGER.debug("test_register_unsupported_media: OK")


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
