import json
import logging
from hashlib import sha256

import pytest
from flask import Flask

import datetime
from moe_gthr_auth_server import register_blueprints, register_error_handlers
from moe_gthr_auth_server.database_ops import (
    Admin,
    PackageContent,
    Package,
    U_Package,
    User,
    add_admin,
    add_package,
    add_package_content,
    add_u_package,
    db,
    pContentEnum,
    add_user,
)
import random

URLS = {
    "login": "/giris",
    "register": "/k_kayit",
    "register_package": "/p_kayit",
    "register_package_content": "/p_kayit",
}

LOGGER = logging.getLogger(__name__)

ERRORS = {
    "unauthorized": {"status": "error", "message": "unauthorized"},
    "unsupported_media_type": {"status": "error", "message": "unsupported_media_type"},
    "request_data_incomplete": {"status": "error", "message": "request_data_incomplete"},
    "request_data_is_none_or_empty": {"status": "error", "message": "request_data_is_none_or_empty"},
    "not_found": {"status": "error", "message": "not_found"},
    "method_not_allowed": {"status": "error", "message": "method_not_allowed"},
}


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
        test_admin = Admin(name=admin_data["name"], password_hash=admin_data["password_hash"])
        LOGGER.debug("init_db: add test_admin, test_admin: %s", test_admin)
        add_admin(test_admin)
        LOGGER.debug("init_db: added test_admin")
        admin_query = Admin.query.all()
        LOGGER.debug("init_db: admin_query: %s", admin_query)
        user_query = User.query.all()
        LOGGER.debug("init_db: user_query: %s", user_query)

    LOGGER.debug("init_db done")


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture
def user_data():
    return {"name": "test_user", "password_hash": sha256("test_user".encode()).hexdigest()}


@pytest.fixture
def user_data2():
    return {"name": "test_user2", "password_hash": sha256("test_user2".encode()).hexdigest()}


@pytest.fixture
def admin_data():
    return {"name": "test_admin", "password_hash": sha256("test_admin".encode()).hexdigest()}


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


def test_init_db(app, app_ctx, admin_data):
    LOGGER.debug("test_init_db")
    with app.app_context():
        db_admin = Admin.query.all()
        assert admin_data["name"] == db_admin[0].name
        assert admin_data["password_hash"] == db_admin[0].password_hash


def test_login(client):
    LOGGER.debug("test_login")
    response = client.get(URLS["login"])
    assert response.status_code == 401
    assert json.loads(response.data) == ERRORS["unauthorized"]
    LOGGER.debug("test_login done")


def test_register_get(client, admin):
    LOGGER.debug("test_register: get")
    response = client.get(URLS["register"])
    assert response.status_code == 401
    assert json.loads(response.data) == ERRORS["unauthorized"]
    response = client.get(URLS["register"], auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {
        "status": "success",
        "message": "db_content",
        "users": [],
        "packages": [],
        "package_contents": [],
    }


def test_register_post_get(client, user_data, admin, app_ctx):
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
            "packages",
            "package_contents",
        ]
        if key == "status":
            assert json_data[key] == "success"
        elif key == "message":
            assert json_data[key] == "db_content"
        elif key == "users":
            with app_ctx:
                db_users = User.query.all()
                db_users_jsons = [db_u.__json__() for db_u in db_users]
            assert json_data[key] == db_users_jsons


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
    assert json.loads(response.data) == ERRORS["unsupported_media_type"]
    LOGGER.debug("test_register_non_json with admin auth done")

    LOGGER.debug("test_register_non_json with user auth")
    response = client.post(URLS["register"], data=user_data, auth=user)
    assert response.status_code == 401
    assert json.loads(response.data) == ERRORS["unauthorized"]
    LOGGER.debug("test_register_non_json with user auth done")

    LOGGER.debug("test_register_non_json without auth")
    response = client.post(URLS["register"], data=user_data)
    assert response.status_code == 401
    assert json.loads(response.data) == ERRORS["unauthorized"]
    LOGGER.debug("test_register_non_json without auth done")


def test_register_bad_request(client, user_data, admin_data, user, admin):
    LOGGER.debug("test_register_bad_request with incomplete data")
    response = client.post(URLS["register"], json={"name": "test_user"}, auth=admin)
    # assert response.status_code == 400
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
    assert json.loads(response.data) == ERRORS["unsupported_media_type"]
    LOGGER.debug("test_register_bad_request with None data done")

    LOGGER.debug("test_register_bad_request with empty values data")
    response = client.post(URLS["register"], json={"name": "", "password_hash": ""}, auth=admin)
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
        if (db_user := User.query.filter_by(name=login_user_data["name"]).first()) is None:
            LOGGER.debug("login_user: db not have login_user ,adding login_user to db")
            add_user(User(name=login_user_data["name"], password_hash=login_user_data["password_hash"]))
            db_user = User.query.filter_by(name=login_user_data["name"]).first()
            LOGGER.debug("login_user: added and queried db_user: %s", db_user)
        LOGGER.debug("login_user: db_user: %s", db_user)
        db.session.commit()
        return tuple(login_user_data.values())


def test_login_post_package_not_found(client, login_user):
    LOGGER.debug("test_login_post_package_not_found: post,auth with login_user: %s " % ",".join(login_user))
    response = client.post(URLS["login"], auth=login_user)
    assert response.status_code == 404
    assert json.loads(response.data) == {"status": "error", "message": "package_not_found"}


@pytest.fixture
def packet_content_data():
    return {"name": "test_packet_content", "content_value": pContentEnum.moe_gatherer}


@pytest.fixture
def packet_data():
    return {"name": "test_packet", "days": 1, "detail": "test_packet_description"}


@pytest.fixture
def expired_user_packet_data():
    return {"start_date": datetime.datetime(2022, 1, 1, 1), "end_date": datetime.datetime.now() - datetime.timedelta(days=1)}


@pytest.fixture
def login_user_expired_packet(expired_user_packet_data, packet_data, packet_content_data, login_user_data, app_ctx):
    with app_ctx:
        if (user_exists := User.query.filter_by(name=login_user_data["name"]).first()) is None:
            user_exists = User(name=login_user_data["name"], password_hash=login_user_data["password_hash"])
            add_user(user_exists)
            user_exists = User.query.filter_by(name=login_user_data["name"]).first()
        if (packet_content_exists := PackageContent.query.filter_by(name=packet_content_data["name"]).first()) is None:
            packet_content_exists = PackageContent(
                name=packet_content_data["name"],
                content_value=packet_content_data["content_value"],
            )
            add_package_content(packet_content_exists)
            packet_content_exists = PackageContent.query.filter_by(name=packet_content_data["name"]).first()
        if (packet_exists := Package.query.filter_by(name=packet_data["name"]).first()) is None:
            packet_exists = Package(
                name=packet_data["name"],
                packagecontents=[
                    packet_content_exists,
                ],
                days=packet_data["days"],
                detail=packet_data["detail"],
            )
            add_package(packet_exists)
            packet_exists = Package.query.filter_by(name=packet_data["name"]).first()
        add_u_package(
            U_Package(
                base_package=packet_exists,
                start_date=expired_user_packet_data["start_date"],
                end_date=expired_user_packet_data["end_date"],
                user=user_exists,
            )
        )
        db.session.commit()
        db_user = User.query.filter_by(name=login_user_data["name"]).first()
        db_packet = db_user.package
        assert db_packet.end_date < datetime.datetime.now()
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
        if (user_exists := User.query.filter_by(name=login_user_data["name"]).first()) is None:
            user_exists = User(name=login_user_data["name"], password_hash=login_user_data["password_hash"])
            add_user(user_exists)
            user_exists = User.query.filter_by(name=login_user_data["name"]).first()
        if (packet_content_exists := PackageContent.query.filter_by(name=packet_content_data["name"]).first()) is None:
            packet_content_exists = PackageContent(
                name=packet_content_data["name"],
                content_value=packet_content_data["content_value"],
            )
            add_package_content(packet_content_exists)
            packet_content_exists = PackageContent.query.filter_by(name=packet_content_data["name"]).first()
        if (packet_exists := Package.query.filter_by(name=packet_data["name"]).first()) is None:
            packet_exists = Package(
                name=packet_data["name"],
                packagecontents=[
                    packet_content_exists,
                ],
                days=packet_data["days"],
                detail=packet_data["detail"],
            )
            add_package(packet_exists)
            packet_exists = Package.query.filter_by(name=packet_data["name"]).first()
        add_u_package(
            U_Package(
                base_package=packet_exists,
                start_date=datetime.datetime.now(),
                end_date=datetime.datetime.now() + packet_exists.days * datetime.timedelta(minutes=1),
                user=user_exists,
            )
        )
        db.session.commit()
        db_user = User.query.filter_by(name=login_user_data["name"]).first()
        db_packet = db_user.package
        assert db_packet.end_date > datetime.datetime.now()
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
    return {"name": "test_packet_content_extra_user", "content_value": pContentEnum.extra_user}


@pytest.fixture
def login_user_with_extra_user_packet(packet_data, packet_content_extra_user, login_user_data, app_ctx):
    with app_ctx:
        if (user_exists := User.query.filter_by(name=login_user_data["name"]).first()) is None:
            user_exists = User(name=login_user_data["name"], password_hash=login_user_data["password_hash"])
            add_user(user_exists)
            user_exists = User.query.filter_by(name=login_user_data["name"]).first()
        if (packet_content_exists := PackageContent.query.filter_by(name=packet_content_extra_user["name"]).first()) is None:
            packet_content_exists = PackageContent(
                name=packet_content_extra_user["name"],
                content_value=packet_content_extra_user["content_value"],
            )
            add_package_content(packet_content_exists)
            packet_content_exists = PackageContent.query.filter_by(name=packet_content_extra_user["name"]).first()
        if (packet_exists := Package.query.filter_by(name=packet_data["name"]).first()) is None:
            packet_exists = Package(
                name=packet_data["name"],
                packagecontents=[
                    packet_content_exists,
                ],
                days=packet_data["days"],
                detail=packet_data["detail"],
            )
            add_package_content(packet_exists)
            packet_exists = Package.query.filter_by(name=packet_data["name"]).first()
        add_u_package(
            U_Package(
                base_package=packet_exists,
                start_date=datetime.datetime.now(),
                end_date=datetime.datetime.now() + packet_exists.days * datetime.timedelta(minutes=1),
                user=user_exists,
            )
        )
        db.session.commit()
        db_user = User.query.filter_by(name=login_user_data["name"]).first()
        db_packet = db_user.package
        assert db_packet.end_date > datetime.datetime.now()
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
        if (user_exists := User.query.filter_by(name=login_user_data["name"]).first()) is None:
            user_exists = User(name=login_user_data["name"], password_hash=login_user_data["password_hash"])
            add_user(user_exists)
            user_exists = User.query.filter_by(name=login_user_data["name"]).first()
        if (packet_content_exists := PackageContent.query.filter_by(name=packet_content_extra_user["name"]).first()) is None:
            packet_content_exists = PackageContent(
                name=packet_content_extra_user["name"],
                content_value=packet_content_extra_user["content_value"],
            )
            add_package_content(packet_content_exists)
            packet_content_exists = PackageContent.query.filter_by(name=packet_content_extra_user["name"]).first()
        if (packet_exists := Package.query.filter_by(name=packet_data["name"]).first()) is None:
            packet_exists = Package(
                name=packet_data["name"],
                packagecontents=[
                    packet_content_exists,
                ],
                days=packet_data["days"],
                detail=packet_data["detail"],
            )
            add_package(packet_exists)
            packet_exists = Package.query.filter_by(name=packet_data["name"]).first()
        add_u_package(
            U_Package(
                base_package=packet_exists,
                start_date=datetime.datetime.now(),
                end_date=datetime.datetime.now() + packet_exists.days * datetime.timedelta(minutes=1),
                user=user_exists,
            )
        )
        db.session.commit()
        db_user = User.query.filter_by(name=login_user_data["name"]).first()
        db_packet = db_user.package
        assert db_packet.end_date > datetime.datetime.now()
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
def register_package_data(packet_data, packet_content_data):
    return {
        "m_type": "package",
        "model": {
            "name": packet_data["name"],
            "days": packet_data["days"],
            "detail": packet_data["detail"],
            "packagecontents": [],
        },
    }


def test_register_package(client, register_package_data, admin):
    LOGGER.debug("test_register_package: post")
    response = client.post(URLS["register_package"], json=register_package_data, auth=admin)
    assert json.loads(response.data) == {"status": "success", "message": "package_created"}
    assert response.status_code == 200


@pytest.fixture
def register_package_content_data(packet_content_data):
    return {
        "m_type": "package_content",
        "model": {
            "name": packet_content_data["name"],
            "content_value": packet_content_data["content_value"],
        },
    }


def test_register_package_content(client, register_package_data, register_package_content_data, admin):
    LOGGER.debug("test_register_package: post")
    response = client.post(URLS["register_package"], json=register_package_data, auth=admin)
    assert json.loads(response.data) == {"status": "success", "message": "package_created"}
    assert response.status_code == 200
    response = client.post(URLS["register_package"], json=register_package_content_data, auth=admin)
    assert json.loads(response.data) == {"status": "success", "message": "package_content_created"}
    assert response.status_code == 200


@pytest.fixture
def register_package_data2():
    return {
        "m_type": "package",
        "model": {
            "name": "test_packet2",
            "days": 1,
            "detail": "test_packet_description2",
            "packagecontents": [],
        },
    }


@pytest.fixture
def register_package_content_datas():
    pc_datas = []
    pc_value_list = list(pContentEnum)
    for i in range(3):
        content_value = random.choice(pc_value_list)
        pc_value_list.remove(content_value)
        pc_datas.append(
            {
                "m_type": "package_content",
                "model": {
                    "name": "_" + content_value + str(i) + "_",
                    "content_value": content_value,
                },
            }
        )
    return pc_datas


@pytest.fixture
def register_package_with_multiple_contents(client, app_ctx, register_package_data2, register_package_content_datas):
    LOGGER.debug("test_register_package: post")

    for pc_data in register_package_content_datas:
        pc_data_model = PackageContent(name=pc_data["model"]["name"], content_value=pc_data["model"]["content_value"])
        LOGGER.debug("adding pc_data_model: %s", pc_data_model)
        register_package_data2["model"]["packagecontents"].append(pc_data_model.__json__())
        # remove ids because they are not in db
        del register_package_data2["model"]["packagecontents"][-1]["id"]

    return register_package_data2


def test_register_package_with_multiple_contents(client, register_package_with_multiple_contents, admin):
    response = client.post(URLS["register_package"], json=register_package_with_multiple_contents, auth=admin)
    assert json.loads(response.data) == {"status": "success", "message": "package_created"}
    assert response.status_code == 200


def test_register_package_with_multiple_contents_check_db(client, register_package_with_multiple_contents, app_ctx, admin):
    with app_ctx:
        response = client.post(URLS["register_package"], json=register_package_with_multiple_contents, auth=admin)
        assert json.loads(response.data) == {"status": "success", "message": "package_created"}
        assert response.status_code == 200
        db_package = Package.query.filter_by(name=register_package_with_multiple_contents["model"]["name"]).first()
        assert db_package is not None
        assert db_package.name == register_package_with_multiple_contents["model"]["name"]
        assert db_package.days == register_package_with_multiple_contents["model"]["days"]
        assert db_package.detail == register_package_with_multiple_contents["model"]["detail"]
        assert len(db_package.packagecontents) == len(register_package_with_multiple_contents["model"]["packagecontents"])
        for pc in db_package.packagecontents:
            LOGGER.debug("fixture pc_datas: %s", register_package_with_multiple_contents["model"]["packagecontents"])
            assert pc.content_value in [
                pc_data["content_value"] for pc_data in register_package_with_multiple_contents["model"]["packagecontents"]
            ]


def test_register_package_get(client, admin, app_ctx):
    expected_respons_data = {
        "status": "success",
        "message": "db_content",
        "packages": [],
        "package_contents": [],
    }
    with app_ctx:
        db_packages_jsons = [db_p.__json__() for db_p in Package.query.all()]
        db_package_contents_jsons = [db_pc.__json__() for db_pc in PackageContent.query.all()]

        expected_respons_data["packages"] = db_packages_jsons
        expected_respons_data["package_contents"] = db_package_contents_jsons

    LOGGER.debug("test_register_package: get")
    response = client.get(URLS["register_package"], auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == expected_respons_data


def test_401(client):
    LOGGER.debug("test_401")
    response = client.get(URLS["register"])
    assert response.status_code == 401
    assert json.loads(response.data) == ERRORS["unauthorized"]

    response = client.get(URLS["register_package"])
    assert response.status_code == 401
    assert json.loads(response.data) == ERRORS["unauthorized"]

    response = client.get(URLS["login"])
    assert response.status_code == 401
    assert json.loads(response.data) == ERRORS["unauthorized"]

    LOGGER.debug("test_401 done")


def test_404(client):
    LOGGER.debug("test_404")
    response = client.get("/404")
    assert response.status_code == 404
    assert json.loads(response.data) == ERRORS["not_found"]
    LOGGER.debug("test_404 done")


def test_415(client, admin):
    LOGGER.debug("test_415")
    response = client.post(URLS["register"], data="aaa", auth=admin)
    # if admin auth is not provided, it will be 401 instead of 415
    assert response.status_code == 415
    assert json.loads(response.data) == ERRORS["unsupported_media_type"]


def test_register_other_requests(client):
    LOGGER.debug("test_register_other_requests")
    response = client.put(URLS["register"])
    assert response.status_code == 405
    assert json.loads(response.data) == ERRORS["method_not_allowed"]
    response = client.delete(URLS["register"])
    assert response.status_code == 405
    assert json.loads(response.data) == ERRORS["method_not_allowed"]
    LOGGER.debug("test_register_other_requests done")


@pytest.fixture
def random_user_data():
    return {"name": "test_user_" + str(random.randint(0, 10000000)), "password_hash": "test_password"}


@pytest.fixture
def random_user(random_user_data):
    return tuple(random_user_data.values())


@pytest.fixture
def not_registered_user_data():
    return {"name": "test_user_" + str(random.randint(0, 10000000)), "password_hash": "test_password"}


def test_login_post_user_not_registered(client, not_registered_user_data):
    LOGGER.debug("test_login_post_user_not_registered: post")
    response = client.post(URLS["login"], json=not_registered_user_data)
    assert response.status_code == 404
    assert json.loads(response.data) == {"status": "error", "message": "user_cred_not_found"}


def test_register_login_random_data_user(client, random_user_data, random_user, admin):
    LOGGER.debug("register_random_data_user: post")
    response = client.post(URLS["register"], json=random_user_data, auth=admin)
    assert response.status_code == 200
    assert json.loads(response.data) == {"status": "success", "message": "user_created"}
    LOGGER.debug("register_random_data_user: post done")
    LOGGER.debug("login_random_data_user: post")
    response = client.post(URLS["login"], auth=random_user)  # package not found
    assert response.status_code == 404
    assert json.loads(response.data) == {"status": "error", "message": "package_not_found"}
    LOGGER.debug("login_random_data_user: post done")


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
