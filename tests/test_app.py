import json
import logging
from hashlib import sha256

import pytest
from flask import Flask


from moe_gthr_auth_server import register_blueprints, register_error_handlers
from moe_gthr_auth_server.database_ops import Admin, Kullanici, db

URLS = {
    "login": "/giris",
    "register": "/kayit",
}

LOGGER = logging.getLogger(__name__)


@pytest.fixture
def app():
    app = Flask("moe_gatherer_server")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    LOGGER.debug("app: %s", app)
    register_blueprints(app)
    register_error_handlers(app)
    yield app


@pytest.fixture
def app_ctx(app):
    return app.app_context()


@pytest.fixture(autouse=True)
def init_db(app, admin_data):
    LOGGER.debug("init_db")
    with app.app_context():
        db.init_app(app)
        db.drop_all()
        db.create_all()
        test_admin = Admin(a_adi=admin_data["a_adi"], a_sifre_hash=admin_data["a_sifre"])
        LOGGER.debug("init_db: add test_admin, test_admin: %s", test_admin)
        db.session.add(test_admin)
        db.session.commit()
        LOGGER.debug("init_db: added test_admin")
        admin_query = Admin.query.all()
        LOGGER.debug("init_db: admin_query: %s", admin_query)
        kullanici_query = Kullanici.query.all()
        LOGGER.debug("init_db: kullanici_query: %s", kullanici_query)

    LOGGER.debug("init_db done")


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
def user_data2():
    return {"k_adi": "test_user2", "k_sifre": sha256("test_user2".encode()).hexdigest()}


@pytest.fixture
def admin_data():
    return {"a_adi": "test_admin", "a_sifre": sha256("test_admin".encode()).hexdigest()}


@pytest.fixture
def user(user_data):
    return tuple(user_data.values())


@pytest.fixture
def user2(user_data2):
    return tuple(user_data2.values())


@pytest.fixture
def admin(admin_data):
    return tuple(admin_data.values())


def test_app(client):
    LOGGER.debug("test_app")
    assert client.get("/").status_code == 200
    LOGGER.debug("test_app done")


def test_login(client):
    LOGGER.debug("test_login")
    assert client.get(URLS["login"]).status_code == 404
    LOGGER.debug("test_login done")


def test_register_get(client, admin):
    LOGGER.debug("test_register")
    assert client.get(URLS["register"]).status_code == 400
    assert client.get(URLS["register"], auth=admin).status_code == 200


def test_register_post_get(client, user_data, admin_data, admin, app_ctx):
    LOGGER.debug("test_register: post")
    response = client.post(URLS["register"], json=user_data, auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_created"}

    LOGGER.debug("test_register: get")
    response = client.get(URLS["register"], auth=admin)
    LOGGER.debug("test_register: get")
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


def test_register_post_user_already_exits(client, user_data2, admin):
    LOGGER.debug("creating user2")
    response = client.post(URLS["register"], json=user_data2, auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {
        "status": "success",
        "message": "user_created",
    }
    LOGGER.debug("creating user2 done")
    LOGGER.debug("creating user2 again")
    response = client.post(URLS["register"], json=user_data2, auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {
        "status": "error",
        "message": "user_already_exists",
    }
    LOGGER.debug("creating user2 again done")


def test_register_non_json(client, user_data, user, admin):
    LOGGER.debug("test_register_non_json with admin auth")
    response = client.post(URLS["register"], data=user_data, auth=admin)
    assert response.status_code == 415
    assert json.loads(response.data) == {"status": "error", "message": "unsupported_media_type"}
    LOGGER.debug("test_register_non_json with admin auth done")

    LOGGER.debug("test_register_non_json with user auth")
    response = client.post(URLS["register"], data=user_data, auth=user)
    assert response.status_code == 401
    assert json.loads(response.data) == {"status": "error", "message": "unauthorized"}
    LOGGER.debug("test_register_non_json with user auth done")

    LOGGER.debug("test_register_non_json without auth")
    response = client.post(URLS["register"], data=user_data)
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "bad_request"}
    LOGGER.debug("test_register_non_json without auth done")


def test_register_bad_request(client, user_data, admin_data, user, admin):
    LOGGER.debug("test_register_bad_request with incomplete data")
    response = client.post(URLS["register"], json={"k_adi": "test_user"}, auth=admin)
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "req_data_incomplete"}
    LOGGER.debug("test_register_bad_request with incomplete data done")

    LOGGER.debug("test_register_bad_request with empty data")
    response = client.post(URLS["register"], json={}, auth=admin)
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "req_data_is_none_or_empty"}
    LOGGER.debug("test_register_bad_request with empty data done")

    LOGGER.debug("test_register_bad_request with None data")
    response = client.post(URLS["register"], json=None, auth=admin)
    assert response.status_code == 415
    assert json.loads(response.data) == {"status": "error", "message": "unsupported_media_type"}
    LOGGER.debug("test_register_bad_request with None data done")

    LOGGER.debug("test_register_bad_request with empty values data")
    response = client.post(URLS["register"], json={"k_adi": "", "k_sifre": ""}, auth=admin)
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "req_data_is_none_or_empty"}
    LOGGER.debug("test_register_bad_request with empty values data done")


# TODO: test_register_bad_request with bad data
# TODO: write more tests for login


def test_login_post_user_not_found(client, user_data):
    LOGGER.debug("test_login_post_user_not_found: post")
    response = client.post(URLS["login"], json=user_data)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "error", "message": "user_not_found"}


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
