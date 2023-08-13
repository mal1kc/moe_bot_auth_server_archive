import json
from hashlib import sha256

import pytest

from moe_gthr_auth_server import register_blueprints, register_extensions, register_modifications
from moe_gthr_auth_server.database_ops import Admin
from moe_gthr_auth_server.database_ops import db
from flask import Flask

urls = {
    "login": "/giris",
    "register": "/kayit",
}


@pytest.fixture
def app():
    app = Flask("moe_gatherer_server")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    register_blueprints(app)
    yield app


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield app


@pytest.fixture(autouse=True)
def init_db(app, admin):
    with app.app_context():
        db.init_app(app)
        db.drop_all()
        db.create_all()
        test_admin = Admin(a_adi=admin[0], a_sifre_hash=sha256(admin[1].encode()).hexdigest())
        db.session.add(test_admin)
        db.session.commit()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture
def admin(app):
    return ("test_admin", sha256("test_admin".encode()).hexdigest())


@pytest.fixture
def user_data():
    return {"k_adi": "test_user", "k_sifre": sha256("test_user".encode()).hexdigest()}


@pytest.fixture
def user_data_dict():
    return {"username": "test_user", "password": sha256("test_user".encode()).hexdigest()}


@pytest.fixture
def admin_data():
    return {"a_adi": "test_admin", "a_sifre": sha256("test_admin".encode()).hexdigest()}


def test_app(client):
    assert client.get("/").status_code == 200


def test_login(client):
    assert client.get(urls["login"]).status_code == 404


def test_register(client, user_data, admin_data):
    assert client.get(urls["register"]).status_code == 400
    response = client.post(urls["register"], data=user_data, auth=admin_data)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_created"}
    response = client.post(urls["register"], data=user_data, auth=admin_data)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "error", "message": "user_already_exists"}


def test_login_post(client, user_data_tuple):
    response = client.post(urls["login"], data=user_data_tuple)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "error", "message": "user_not_found"}
    response = client.post(urls["login"], auth=user_data_tuple)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_logged_in"}
