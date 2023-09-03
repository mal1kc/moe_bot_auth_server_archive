import pytest
import datetime

from moe_gthr_auth_server.crpytion import (
    make_password_hash,
    encryption_password,
    simple_dencrypt,
    encoding,
)
from moe_gthr_auth_server.enums import mType

from tests.testing_helpers import show_db_data, LOGGER, URLS, utc_timestamp


def test_register_user(client, user_data, admin_data_auth):
    LOGGER.debug("test_register_user")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user: OK")


def test_register_unsupported_media(client, admin_data_auth):
    LOGGER.debug("test_register_unsupported_media")
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        data="some data",
        content_type="text/plain",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "unsupported_media_type", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 415
    LOGGER.debug("test_register_unsupported_media: OK")


def test_register_user_no_auth(client, user_data):
    LOGGER.debug("test_register_user_no_auth")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "unauthorized", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 401
    LOGGER.debug("test_register_user_no_auth: OK")


def test_register_user_already_exists(client, app_ctx, user_data, admin_data_auth):
    LOGGER.debug("test_register_user_already_exist")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_already_exists", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_user_already_exist: OK")
    show_db_data(app_ctx)


def test_register_user_passhash_too_short(client, user_data, admin_data_auth):
    "probably will never happen, but just in case"
    LOGGER.debug("test_register_user_passhash_too_short")

    def make_password_ready(password: str) -> str:
        def make_short_password_hash(password: str) -> str:
            return make_password_hash(password)[:10]

        password_hash = make_short_password_hash(password)
        return simple_dencrypt(password_hash.encode(encoding), encryption_password).hex()

    user_data["password_hash"] = make_password_ready("ext_test_user_password")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_passhash_too_short", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_user_passhash_too_short: OK")


def test_register_user_name_too_short(client, user_data, admin_data_auth):
    LOGGER.debug("test_register_user_name_too_short")

    def make_short_name(name: str) -> str:
        return name[:2]

    user_data["name"] = make_short_name("ext_test_user")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_name_too_short", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_user_name_too_short: OK")


def test_register_user_name_too_long(client, user_data, admin_data_auth):
    LOGGER.debug("test_register_user_name_too_long")

    def make_long_name(name: str) -> str:
        "256 is the max length of the field in the db"
        return name + "a" * 256

    user_data["name"] = make_long_name("ext_test_user")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_name_too_long", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_user_name_too_long: OK")


def test_register_package_data(client, package_data, admin_data_auth):
    LOGGER.debug("test_register_package_data")
    request_json = {"model": package_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_package_data: OK")


def test_register_package_data_not_valid_data(client, package_data, admin_data_auth):
    # TODO: refactor this error messages and error handling
    LOGGER.debug("test_register_package_data_not_valid_data")
    package_data["package_contents"] = None
    request_json = {"model": None}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["status"] == "error"
    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.status_code == 400
    LOGGER.debug("test_register_package_data_not_valid_data: OK")
    LOGGER.debug("test_register_package_data_not_valid_data: not_valid_name")
    package_data["name"] = None
    request_json = {"model": package_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    assert response.json["message"] == "bad_request", response.json
    assert response.json["status"] == "error"
    assert response.json["error"] == "not_valid_data\nnot_valid_name", response.json
    # FIXME : wtf is this error message
    assert response.status_code == 400
    LOGGER.debug("test_register_package_data_not_valid_data: OK")


def test_register_package_data_with_package_content(
    client, package_data_with_package_content, admin_data_auth
):
    LOGGER.debug("test_register_package_data_with_package_content")
    request_json = {"model": package_data_with_package_content}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_package_data_with_package_content: OK")


def test_register_package_already_exits(client, app_ctx, package_data, admin_data_auth):
    LOGGER.debug("test_register_package_already_exits")
    request_json = {"model": package_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200

    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_already_exists", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_already_exits: OK")
    show_db_data(app_ctx)


def test_register_package_content_data(
    client, random_package_content_data, admin_data_auth
):
    LOGGER.debug("test_register_package_content_data")
    request_json = {"model": random_package_content_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package_content),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_package_content_data: OK")


def test_register_package_content_already_exists(
    client, app_ctx, random_package_content_data, admin_data_auth
):
    LOGGER.debug("test_register_package_content_already_exists")
    request_json = {"model": random_package_content_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package_content),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )

    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200

    response = client.post(
        URLS.ARegister.format(m_type=mType.package_content),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )

    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_already_exists", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_content_already_exists: OK")
    show_db_data(app_ctx)


def test_register_u_package(
    client, u_package_data, user_data, package_data, admin_data_auth
):
    # TODO : warningleri düzelt
    LOGGER.debug("test_register_u_package")
    LOGGER.debug("test_register_u_package: register user")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )

    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200

    u_package_data["user_id"] = response.json["user"]["id"]
    LOGGER.debug("test_register_u_package: register package")

    request_json = {"model": package_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200

    u_package_data["base_package"] = response.json["package"]["id"]

    LOGGER.debug("test_register_u_package: register u_package")
    LOGGER.debug("u_package_data: %s", u_package_data)
    request_json = {"model": u_package_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.u_package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )

    assert response.json["message"] == "u_package_created", response.json
    assert response.json["status"] == "success"
    assert "u_package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_u_package: OK")


def test_register_unsupported_model(client, admin_data_auth):
    LOGGER.debug("test_register_unsupported_model")
    request_json = {"model": {}}
    response = client.post(
        URLS.ARegister.format(m_type=123),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )

    assert response.json["message"] == "unsupported_model_type", response.json
    assert response.json["status"] == "error"
    assert response.json["detail"] == {
        "supported_model_types": ["user", "package", "package_content", "u_package"]
    }
    assert response.status_code == 400
    LOGGER.debug("test_register_unsupported_model: OK")


def test_register_user_package(
    client, user_data_auth, user_data, package_data, admin_data_auth
):
    user_package_data = {
        "user": None,
        "base_package": None,
    }

    LOGGER.debug("test_register_user_package: registering user")
    request_json = {"model": user_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.user),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user_package: registering user: OK")

    user_package_data["user"] = response.json["user"]["id"]

    LOGGER.debug("test_register_user_package: registering package")
    request_json = {"model": package_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user_package: registering package: OK")

    user_package_data["base_package"] = response.json["package"]["id"]

    LOGGER.debug("test_register_user_package: registering user_package")
    user_package_data["start_date"] = utc_timestamp(
        datetime.datetime.now(), return_type=int
    )
    request_json = {"model": user_package_data}
    response = client.post(
        URLS.ARegister.format(m_type=mType.u_package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "u_package_created", response.json
    assert response.json["status"] == "success"
    assert "u_package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user_package: registering user_package: OK")


def test_register_package_with_already_existed_contents(
    client, package_data_with_random_content_datas, admin_data_auth
):
    LOGGER.debug("test_register_package_with_already_existed_contents: register package")
    request_json = {
        "model": package_data_with_random_content_datas,
    }
    response = client.post(
        URLS.ARegister.format(m_type=mType.package),
        json=request_json,
        content_type="application/json",
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["status"] == "error"
    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_already_exists"
    assert response.status_code == 400
    LOGGER.debug(
        "test_register_package_with_already_existed_contents: registering package: OK"
    )


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
