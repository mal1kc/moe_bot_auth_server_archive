import json
import logging
from hashlib import sha256

import pytest
from flask import Flask, session

import datetime
from moe_gthr_auth_server import register_blueprints, register_error_handlers
from moe_gthr_auth_server.database_ops import Admin, K_Paket, Kullanici, Paket, PaketIcerik, db, pIcerik

URLS = {
    "login": "/giris",
    "register": "/k_kayit",
    "register_packet": "/p_kayit",
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
    return {"k_ad": "test_user", "k_sifre": sha256("test_user".encode()).hexdigest()}


@pytest.fixture
def user_data2():
    return {"k_ad": "test_user2", "k_sifre": sha256("test_user2".encode()).hexdigest()}


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
    response = client.get(URLS["login"])
    assert response.status_code == 401
    assert json.loads(response.data) == {"status": "error", "message": "unauthorized"}
    LOGGER.debug("test_login done")


def test_register_get(client, admin):
    LOGGER.debug("test_register: get")
    response = client.get(URLS["register"])
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "bad_request"}
    response = client.get(URLS["register"], auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {
        "status": "success",
        "message": "db_content",
        "users": [],
        "packets": [],
        "packet_contents": [],
    }


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
    response = client.post(URLS["register"], json={"k_ad": "test_user"}, auth=admin)
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "request_data_incomplete"}
    LOGGER.debug("test_register_bad_request with incomplete data done")

    LOGGER.debug("test_register_bad_request with empty data")
    response = client.post(URLS["register"], json={}, auth=admin)
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "request_data_is_none_or_empty"}
    LOGGER.debug("test_register_bad_request with empty data done")

    LOGGER.debug("test_register_bad_request with None data")
    response = client.post(URLS["register"], json=None, auth=admin)
    assert response.status_code == 415
    assert json.loads(response.data) == {"status": "error", "message": "unsupported_media_type"}
    LOGGER.debug("test_register_bad_request with None data done")

    LOGGER.debug("test_register_bad_request with empty values data")
    response = client.post(URLS["register"], json={"k_ad": "", "k_sifre": ""}, auth=admin)
    assert response.status_code == 400
    assert json.loads(response.data) == {"status": "error", "message": "request_data_is_none_or_empty"}
    LOGGER.debug("test_register_bad_request with empty values data done")


# TODO: test_register_bad_request with bad data
# TODO: write more tests for login


def test_login_post_user_not_found(client, user_data):
    LOGGER.debug("test_login_post_user_not_found: post")
    response = client.post(URLS["login"], json=user_data)
    assert response.status_code == 404
    assert json.loads(response.data) == {"status": "error", "message": "user_cred_not_found"}


@pytest.fixture
def login_user_data(user_data):
    return user_data


@pytest.fixture
def login_user(app_ctx, login_user_data):
    with app_ctx:
        if (db_user := Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()) is None:
            LOGGER.debug("login_user: db not have login_user ,adding login_user to db")
            db.session.add(Kullanici(k_ad=login_user_data["k_ad"], k_sifre_hash=login_user_data["k_sifre"]))
            db_user = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
            LOGGER.debug("login_user: added and queried db_user: %s", db_user)
        LOGGER.debug("login_user: db_user: %s", db_user)
        db.session.commit()
        return tuple(login_user_data.values())


def test_login_post_packet_not_found(client, login_user):
    LOGGER.debug("test_login_post_packet_not_found: post,auth with login_user: %s " % ",".join(login_user))
    response = client.post(URLS["login"], auth=login_user)
    assert response.status_code == 404
    assert json.loads(response.data) == {"status": "error", "message": "packet_not_found"}


@pytest.fixture
def packet_content_data():
    return {"p_icerikAd": "test_packet_content", "p_icerikDeger": pIcerik.moe_gatherer}


@pytest.fixture
def packet_data():
    return {"p_ad": "test_packet", "p_gun": 1, "p_aciklama": "test_packet_description"}


@pytest.fixture
def expired_user_packet_data():
    return {"k_pBaslangic": datetime.datetime(2022, 1, 1, 1), "k_pBitis": datetime.datetime.now() - datetime.timedelta(days=1)}


@pytest.fixture
def login_user_expired_packet(expired_user_packet_data, packet_data, packet_content_data, login_user_data, app_ctx):
    with app_ctx:
        if (user_exists := Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()) is None:
            user_exists = Kullanici(k_ad=login_user_data["k_ad"], k_sifre_hash=login_user_data["k_sifre"])
            db.session.add(user_exists)
            user_exists = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        if (packet_content_exists := PaketIcerik.query.filter_by(p_icerikAd=packet_content_data["p_icerikAd"]).first()) is None:
            packet_content_exists = PaketIcerik(
                p_icerikAd=packet_content_data["p_icerikAd"],
                p_icerikDeger=packet_content_data["p_icerikDeger"],
            )
            db.session.add(packet_content_exists)
            packet_content_exists = PaketIcerik.query.filter_by(p_icerikAd=packet_content_data["p_icerikAd"]).first()
        if (packet_exists := Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()) is None:
            packet_exists = Paket(
                p_ad=packet_data["p_ad"],
                p_icerikler=[
                    packet_content_exists,
                ],
                p_gun=packet_data["p_gun"],
                p_aciklama=packet_data["p_aciklama"],
            )
            db.session.add(packet_exists)
            packet_exists = Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()
        db.session.add(
            K_Paket(
                k_pTur=packet_exists,
                k_pBaslangic=expired_user_packet_data["k_pBaslangic"],
                k_pBitis=expired_user_packet_data["k_pBitis"],
                k_pKullanici=user_exists,
            )
        )
        db.session.commit()
        db_user = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        db_packet = db_user.k_paket
        assert db_packet.k_pBitis < datetime.datetime.now()
        db.session.commit()
        return tuple(login_user_data.values())


def test_login_post_packet_expired(client, login_user_expired_packet):
    LOGGER.debug("test_login_post_packet_expired: post,auth with expired_user_packet_data: %s " % ",".join(login_user_expired_packet))
    response = client.post(URLS["login"], auth=login_user_expired_packet)
    assert response.status_code == 410
    assert json.loads(response.data) == {"status": "error", "message": "packet_time_expired"}


@pytest.fixture
def login_user_with_packet(packet_data, packet_content_data, login_user_data, app_ctx):
    with app_ctx:
        if (user_exists := Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()) is None:
            user_exists = Kullanici(k_ad=login_user_data["k_ad"], k_sifre_hash=login_user_data["k_sifre"])
            db.session.add(user_exists)
            user_exists = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        if (packet_content_exists := PaketIcerik.query.filter_by(p_icerikAd=packet_content_data["p_icerikAd"]).first()) is None:
            packet_content_exists = PaketIcerik(
                p_icerikAd=packet_content_data["p_icerikAd"],
                p_icerikDeger=packet_content_data["p_icerikDeger"],
            )
            db.session.add(packet_content_exists)
            packet_content_exists = PaketIcerik.query.filter_by(p_icerikAd=packet_content_data["p_icerikAd"]).first()
        if (packet_exists := Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()) is None:
            packet_exists = Paket(
                p_ad=packet_data["p_ad"],
                p_icerikler=[
                    packet_content_exists,
                ],
                p_gun=packet_data["p_gun"],
                p_aciklama=packet_data["p_aciklama"],
            )
            db.session.add(packet_exists)
            packet_exists = Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()
        db.session.add(
            K_Paket(
                k_pTur=packet_exists,
                k_pBaslangic=datetime.datetime.now(),
                k_pBitis=datetime.datetime.now() + packet_exists.p_gun * datetime.timedelta(minutes=1),
                k_pKullanici=user_exists,
            )
        )
        db.session.commit()
        db_user = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        db_packet = db_user.k_paket
        assert db_packet.k_pBitis > datetime.datetime.now()
        db.session.commit()
        return tuple(login_user_data.values())


def test_login_post_max_online_user1(client, login_user_with_packet):
    LOGGER.debug("test_login_post_max_online_user1: post,auth with login_user_with_packet: %s " % ",".join(login_user_with_packet))
    response = client.post(URLS["login"], auth=login_user_with_packet)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_logged_in"}
    LOGGER.debug("test_login_post_max_online_user1: post,auth with login_user_with_packet: %s " % ",".join(login_user_with_packet))
    response = client.post(URLS["login"], auth=login_user_with_packet)
    assert response.status_code == 401
    assert json.loads(response.data) == {"status": "error", "message": "maximum_online_user_quota"}


@pytest.fixture
def packet_content_extra_user():
    return {"p_icerikAd": "test_packet_content_extra_user", "p_icerikDeger": pIcerik.extra_user}


@pytest.fixture
def login_user_with_extra_user_packet(packet_data, packet_content_extra_user, login_user_data, app_ctx):
    with app_ctx:
        if (user_exists := Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()) is None:
            user_exists = Kullanici(k_ad=login_user_data["k_ad"], k_sifre_hash=login_user_data["k_sifre"])
            db.session.add(user_exists)
            user_exists = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        if (packet_content_exists := PaketIcerik.query.filter_by(p_icerikAd=packet_content_extra_user["p_icerikAd"]).first()) is None:
            packet_content_exists = PaketIcerik(
                p_icerikAd=packet_content_extra_user["p_icerikAd"],
                p_icerikDeger=packet_content_extra_user["p_icerikDeger"],
            )
            db.session.add(packet_content_exists)
            packet_content_exists = PaketIcerik.query.filter_by(p_icerikAd=packet_content_extra_user["p_icerikAd"]).first()
        if (packet_exists := Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()) is None:
            packet_exists = Paket(
                p_ad=packet_data["p_ad"],
                p_icerikler=[
                    packet_content_exists,
                ],
                p_gun=packet_data["p_gun"],
                p_aciklama=packet_data["p_aciklama"],
            )
            db.session.add(packet_exists)
            packet_exists = Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()
        db.session.add(
            K_Paket(
                k_pTur=packet_exists,
                k_pBaslangic=datetime.datetime.now(),
                k_pBitis=datetime.datetime.now() + packet_exists.p_gun * datetime.timedelta(minutes=1),
                k_pKullanici=user_exists,
            )
        )
        db.session.commit()
        db_user = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        db_packet = db_user.k_paket
        assert db_packet.k_pBitis > datetime.datetime.now()
        db.session.commit()
        return tuple(login_user_data.values())


def test_login_post_max_online_user2(client, login_user_with_extra_user_packet):
    LOGGER.debug(
        "test_login_post_max_online_user2: post,auth with login_user_with_extra_user_packet: %s "
        % ",".join(login_user_with_extra_user_packet)
    )
    response = client.post(URLS["login"], auth=login_user_with_extra_user_packet)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_logged_in"}
    LOGGER.debug(
        "test_login_post_max_online_user2: post,auth with login_user_with_extra_user_packet: %s "
        % ",".join(login_user_with_extra_user_packet)
    )
    response = client.post(URLS["login"], auth=login_user_with_extra_user_packet)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_logged_in"}

    LOGGER.debug(
        "test_login_post_max_online_user2: post,auth with login_user_with_extra_user_packet: %s "
        % ",".join(login_user_with_extra_user_packet)
    )
    response = client.post(URLS["login"], auth=login_user_with_extra_user_packet)
    assert response.status_code == 401
    assert json.loads(response.data) == {"status": "error", "message": "maximum_online_user_quota"}


@pytest.fixture
def login_user_with_2_extra_user_packet(packet_data, packet_content_extra_user, login_user_data, app_ctx):
    with app_ctx:
        if (user_exists := Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()) is None:
            user_exists = Kullanici(k_ad=login_user_data["k_ad"], k_sifre_hash=login_user_data["k_sifre"])
            db.session.add(user_exists)
            user_exists = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        if (packet_content_exists := PaketIcerik.query.filter_by(p_icerikAd=packet_content_extra_user["p_icerikAd"]).first()) is None:
            packet_content_exists = PaketIcerik(
                p_icerikAd=packet_content_extra_user["p_icerikAd"],
                p_icerikDeger=packet_content_extra_user["p_icerikDeger"],
            )
            db.session.add(packet_content_exists)
            packet_content_exists = PaketIcerik.query.filter_by(p_icerikAd=packet_content_extra_user["p_icerikAd"]).first()
        if (packet_exists := Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()) is None:
            packet_exists = Paket(
                p_ad=packet_data["p_ad"],
                p_icerikler=[
                    packet_content_exists,
                ],
                p_gun=packet_data["p_gun"],
                p_aciklama=packet_data["p_aciklama"],
            )
            db.session.add(packet_exists)
            packet_exists = Paket.query.filter_by(p_ad=packet_data["p_ad"]).first()
        db.session.add(
            K_Paket(
                k_pTur=packet_exists,
                k_pBaslangic=datetime.datetime.now(),
                k_pBitis=datetime.datetime.now() + packet_exists.p_gun * datetime.timedelta(minutes=1),
                k_pKullanici=user_exists,
            )
        )
        db.session.commit()
        db_user = Kullanici.query.filter_by(k_ad=login_user_data["k_ad"]).first()
        db_packet = db_user.k_paket
        assert db_packet.k_pBitis > datetime.datetime.now()
        db.session.commit()
        return tuple(login_user_data.values())


def test_login_post_max_online_user3(client, login_user_with_extra_user_packet):
    LOGGER.debug("test_login_post_max_online_user3, post 1")
    response = client.post(URLS["login"], auth=login_user_with_extra_user_packet)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_logged_in"}
    LOGGER.debug("test_login_post_max_online_user3, post 2")
    response = client.post(URLS["login"], auth=login_user_with_extra_user_packet)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_logged_in"}
    LOGGER.debug("test_login_post_max_online_user3, post 3")
    response = client.post(URLS["login"], auth=login_user_with_extra_user_packet)
    assert response.status_code == 401
    assert json.loads(response.data) == {"status": "error", "message": "maximum_online_user_quota"}
    LOGGER.debug("test_login_post_max_online_user3, post 4")
    response = client.post(URLS["login"], auth=login_user_with_extra_user_packet)
    assert response.status_code == 401
    assert json.loads(response.data) == {"status": "error", "message": "maximum_online_user_quota"}


@pytest.fixture
def register_packet_data(packet_data, packet_content_data):
    return {
        "m_type": "paket",
        "model": {
            "p_ad": packet_data["p_ad"],
            "p_gun": packet_data["p_gun"],
            "p_aciklama": packet_data["p_aciklama"],
            "p_icerikler": [],
        },
    }


def test_register_packet(client, register_packet_data, admin):
    LOGGER.debug("test_register_packet: post")
    response = client.post(URLS["register_packet"], json=register_packet_data)
    assert json.loads(response.data) == {"status": "success", "message": "paket_created"}
    assert response.status_code == 200


@pytest.fixture
def register_packet_content_data(packet_content_data):
    return {
        "m_type": "paket_icerik",
        "model": {
            "p_icerikAd": packet_content_data["p_icerikAd"],
            "p_icerikDeger": packet_content_data["p_icerikDeger"],
        },
    }


def test_register_packet_content(client, register_packet_data, admin, register_packet_content_data):
    LOGGER.debug("test_register_packet: post")
    response = client.post(URLS["register_packet"], json=register_packet_data)
    assert json.loads(response.data) == {"status": "success", "message": "paket_created"}
    assert response.status_code == 200
    response = client.post(URLS["register_packet"], json=register_packet_content_data)
    assert json.loads(response.data) == {"status": "success", "message": "paket_icerik_created"}
    assert response.status_code == 200


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
