import json
import logging
from hashlib import sha256

import pytest
from flask import Flask

from moe_gthr_auth_server import (register_blueprints, register_extensions,
                                  register_modifications)
from moe_gthr_auth_server.database_ops import Admin, Kullanici, db

urls = {
    "login": "/giris",
    "register": "/kayit",
}

logger = logging.getLogger(__name__)


@pytest.fixture
def app():
    app = Flask("moe_gatherer_server")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    logger.debug("app: %s", app)
    register_blueprints(app)
    yield app


@pytest.fixture
def app_ctx(app):
    return app.app_context()


@pytest.fixture(autouse=True)
def init_db(app, admin_data):
    logger.debug("init_db")
    with app.app_context():
        db.init_app(app)
        db.drop_all()
        db.create_all()
        test_admin = Admin(
            a_adi=admin_data["a_adi"], a_sifre_hash=admin_data["a_sifre"]
        )
        logger.debug("init_db: add test_admin, test_admin: %s", test_admin)
        db.session.add(test_admin)
        db.session.commit()
        logger.debug("init_db: added test_admin")
        admin_query = Admin.query.all()
        logger.debug("init_db: admin_query: %s", admin_query)
        kullanici_query = Kullanici.query.all()
        logger.debug("init_db: kullanici_query: %s", kullanici_query)

    logger.debug("init_db done")


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture
def user_data():
    return {"k_adi": "test_user", "k_sifre": sha256("test_user".encode()).hexdigest()}


@pytest.fixture
def admin_data():
    return {"a_adi": "test_admin", "a_sifre": sha256("test_admin".encode()).hexdigest()}


@pytest.fixture
def user(user_data):
    return tuple(user_data.values())


@pytest.fixture
def admin(admin_data):
    return tuple(admin_data.values())


def test_app(client):
    logger.debug("test_app")
    assert client.get("/").status_code == 200
    logger.debug("test_app done")


def test_login(client):
    logger.debug("test_login")
    assert client.get(urls["login"]).status_code == 404
    logger.debug("test_login done")


def test_register(client, user_data, admin_data, user, admin, app_ctx):
    logger.debug("test_register")
    assert client.get(urls["register"]).status_code == 400
    logger.debug(
        "test_register: post, user_data: %s, admin_data: %s", user_data, admin_data
    )
    response = client.post(urls["register"], json=user_data, auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_created"}
    logger.debug(
        "test_register: post 2, user_data: %s, admin_data: %s", user_data, admin_data
    )
    response = client.post(urls["register"], json=user_data, auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {
        "status": "error",
        "message": "user_already_exists",
    }
    logger.debug("test_register done")

    logger.debug("test_register: get, admin_data: %s", admin_data)
    response = client.get(urls["register"], auth=admin)
    logger.debug(
        "test_register: get, admin_data: %s, response: %s", admin_data, response
    )
    assert response.status_code == 200
    json_data = json.loads(response.data)
    for key in json_data.keys():
        assert key in [
            "status",
            "message",
            "users",
            "token",
            "packets",
            "packet_contents",
        ]
        if key == "status":
            assert json_data[key] == "success"
        elif key == "message":
            assert json_data[key] == "db_content"
        elif key == "users":
            with app_ctx:
                db_users = Kullanici.query.all()
            assert json_data[key] == [db_u.__json__() for db_u in db_users]


def test_login_post_user_not_found(client, user_data):
    logger.debug("test_login_post_user_not_found: post, user_data: %s", user_data)
    response = client.post(urls["login"], json=user_data)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "error", "message": "user_not_found"}


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
