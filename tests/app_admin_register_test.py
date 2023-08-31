import pytest
import random

from moe_gthr_auth_server.database_ops import (
    pContentEnum,
)

from moe_gthr_auth_server.crpytion import (
    make_password_hash,
    encryption_password,
    simple_dencrypt,
    encoding,
    make_password_ready,
)

from tests.testing_helpers import show_db_data, LOGGER, URLS


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


def test_register_user_no_auth(client, user_data):
    LOGGER.debug("test_register_user_no_auth")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json")
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "unauthorized", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 401
    LOGGER.debug("test_register_user_no_auth: OK")


def test_register_user_already_exists(client, app_ctx, user_data, admin_data_auth):
    LOGGER.debug("test_register_user_already_exist")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
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
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
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
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
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
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_name_too_long", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_user_name_too_long: OK")


def test_register_package_data(client, package_data, admin_data_auth):
    LOGGER.debug("test_register_package_data")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_package_data: OK")


def test_register_package_data_invalid_package_contents(client, package_data, admin_data_auth):
    LOGGER.debug("test_register_package_data_invalid_package_contents")
    package_data["package_contents"] = None
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_data_invalid_package_contents: OK")


def test_register_package_data_with_package_content(client, package_data_with_package_content, admin_data_auth):
    LOGGER.debug("test_register_package_data_with_package_content")
    request_json = {"model_type": "package", "model": package_data_with_package_content}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_package_data_with_package_content: OK")


def test_register_package_already_exits(client, app_ctx, package_data, admin_data_auth):
    LOGGER.debug("test_register_package_already_exits")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200

    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_already_exists", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_already_exits: OK")
    show_db_data(app_ctx)


def test_register_package_content_data(client, random_package_content_data, admin_data_auth):
    LOGGER.debug("test_register_package_content_data")
    request_json = {"model_type": "package_content", "model": random_package_content_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)

    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_package_content_data: OK")


def test_register_package_content_invalid_or_empty(client, random_package_content_data, admin_data_auth):
    LOGGER.debug("test_register_package_content_invalid_or_empty")
    request_json = {"model_type": "package_content", "model": None}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_content_invalid_or_empty: 1 OK")

    request_json = {"model_type": "package_content", "model": {}}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_content_invalid_or_empty: 2 OK")
    random_package_content_data["name"] = None
    request_json = {"model_type": "package_content", "model": random_package_content_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_content_invalid_or_empty: 3 OK")


def test_register_package_content_already_exists(client, app_ctx, random_package_content_data, admin_data_auth):
    LOGGER.debug("test_register_package_content_already_exists")
    request_json = {"model_type": "package_content", "model": random_package_content_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200

    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "db_error", response.json
    assert response.json["db_operation_result"] == "model_already_exists", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_register_package_content_already_exists: OK")
    show_db_data(app_ctx)


def test_register_u_package(client, u_package_data, user_data, package_data, admin_data_auth):
    # TODO : warningleri düzelt
    LOGGER.debug("test_register_u_package")
    LOGGER.debug("test_register_u_package: register user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200

    u_package_data["user"] = response.json["user"]["id"]
    LOGGER.debug("test_register_u_package: register package")

    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200

    u_package_data["base_package"] = response.json["package"]["id"]

    LOGGER.debug("test_register_u_package: register u_package")
    LOGGER.debug("u_package_data: %s", u_package_data)
    request_json = {"model_type": "u_package", "model": u_package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "u_package_created", response.json
    assert response.json["status"] == "success"
    assert "u_package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_u_package: OK")


def test_register_unsupported_model(client, admin_data_auth):
    LOGGER.debug("test_register_unsupported_model")
    request_json = {"model_type": "unsupported_model", "model": {}}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "unsupported_model_type", response.json
    assert response.json["status"] == "error"
    assert response.json["detail"] == {"supported_model_types": ["user", "package", "package_content", "u_package"]}
    assert response.status_code == 400
    LOGGER.debug("test_register_unsupported_model: OK")


def test_login_without_u_package(client, user_data_auth, user_data, admin_data_auth):
    LOGGER.debug("test_login: registering user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_login: registering user: OK")

    LOGGER.debug("test_login: logging in user")
    response = client.post(URLS.ULogin, auth=user_data_auth)
    assert response.json["message"] == "package_not_found", response.json
    assert response.json["status"] == "error"
    LOGGER.debug("test_login: logging in user: response_json %s", response.json)
    assert response.status_code == 404
    LOGGER.debug("test_login: logging in user: OK")


def test_login_with_u_package(
    client, user_data_auth, user_data, package_data, random_package_content_data, u_package_data, admin_data_auth
):
    # TODO: warningleri düzelt
    LOGGER.debug("test_login_with_u_package")
    LOGGER.debug("test_login_with_u_package: registering user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_login_with_u_package: registering user: OK")

    u_package_data["user"] = response.json["user"]["id"]

    LOGGER.debug("test_login_with_u_package: registering package_content")
    request_json = {"model_type": "package_content", "model": random_package_content_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_login_with_u_package: registering package_content: OK")

    package_data["package_contents"] = [response.json["package_content"]["id"]]
    LOGGER.debug("test_login_with_u_package: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_login_with_u_package: registering package: OK")

    u_package_data["base_package"] = response.json["package"]["id"]

    LOGGER.debug("test_login_with_u_package: registering u_package")
    request_json = {"model_type": "u_package", "model": u_package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "u_package_created", response.json
    assert response.json["status"] == "success"
    assert "u_package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_login_with_u_package: registering u_package: OK")

    LOGGER.debug("test_login_with_u_package: logging in user")
    response = client.post(URLS.ULogin, auth=user_data_auth)
    assert response.json["message"] == "login_success", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_login_with_u_package: logging in user: OK")


def test_update_user_data(client, user_data, admin_data_auth, sample_update_user_data, app_ctx):
    LOGGER.debug("test_update_user_data: registering user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_user_data: registering user: OK")

    sample_update_user_data["id"] = response.json["user"]["id"]
    LOGGER.debug("test_update_user_data: updating user")
    LOGGER.debug("sample_update_user_data: %s", sample_update_user_data)
    request_json = {"model_type": "user", "model": sample_update_user_data}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "user_updated", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_user_data: updating user: OK")
    show_db_data(app_contx=app_ctx)


def test_update_user_data_invalid_or_empty(client, user_data, admin_data_auth, sample_update_user_data, app_ctx):
    LOGGER.debug("test_update_user_data_invalid_or_empty: registering user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_user_data_invalid_or_empty: registering user: OK")

    sample_update_user_data["id"] = response.json["user"]["id"]
    LOGGER.debug("test_update_user_data_invalid_or_empty: updating user")
    LOGGER.debug("sample_update_user_data: %s", sample_update_user_data)
    request_json = {"model_type": "user", "model": None}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_update_user_data_invalid_or_empty: updating user: OK")


def test_update_package_data(client, package_data, admin_data_auth, sample_update_package_data, app_ctx):
    LOGGER.debug("test_update_package_data: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_data: registering package: OK")

    sample_update_package_data["id"] = response.json["package"]["id"]
    LOGGER.debug("test_update_package_data: updating package")
    LOGGER.debug("sample_update_package_data: %s", sample_update_package_data)
    request_json = {"model_type": "package", "model": sample_update_package_data}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "package_updated", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_data: updating package: OK")
    show_db_data(app_contx=app_ctx)


def test_update_package_data_invalid_or_empty(client, package_data, admin_data_auth, sample_update_package_data, app_ctx):
    LOGGER.debug("test_update_package_data_invalid_or_empty: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_data_invalid_or_empty: registering package: OK")

    sample_update_package_data["id"] = response.json["package"]["id"]
    LOGGER.debug("test_update_package_data_invalid_or_empty: updating package")
    LOGGER.debug("sample_update_package_data: %s", sample_update_package_data)
    request_json = {"model_type": "package", "model": None}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)
    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_update_package_data_invalid_or_empty: updating package: OK")


def test_update_package_data_invalid_package_contents(client, package_data, admin_data_auth, sample_update_package_data, app_ctx):
    LOGGER.debug("test_update_package_data_invalid_package_contents: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200

    sample_update_package_data["id"] = response.json["package"]["id"]
    LOGGER.debug("test_update_package_data_invalid_package_contents: updating package")
    LOGGER.debug("sample_update_package_data: %s", sample_update_package_data)
    sample_update_package_data["package_contents"] = None
    request_json = {"model_type": "package", "model": sample_update_package_data}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "request_data_is_none_or_empty", response.json
    assert response.json["status"] == "error"
    assert response.status_code == 400
    LOGGER.debug("test_update_package_data_invalid_package_contents: updating package: OK")


def test_update_package_content_data(
    client, random_package_content_data, admin_data_auth, sample_update_package_content_data, app_ctx
):
    LOGGER.debug("test_update_package_content_data: registering package_content")
    request_json = {"model_type": "package_content", "model": random_package_content_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200

    sample_update_package_content_data["id"] = response.json["package_content"]["id"]
    LOGGER.debug("test_update_package_content_data: updating package_content")
    LOGGER.debug("sample_update_package_content_data: %s", sample_update_package_content_data)
    request_json = {"model_type": "package_content", "model": sample_update_package_content_data}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "package_content_updated", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_content_data: updating package_content: OK")
    show_db_data(app_contx=app_ctx)


def test_update_u_package_data(
    client, user_data, package_data, u_package_data, admin_data_auth, sample_update_u_package_data, app_ctx
):
    LOGGER.debug("test_update_u_package_data: registering user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_u_package_data: registering user: OK")
    u_package_data["user"] = response.json["user"]["id"]
    LOGGER.debug("test_update_u_package_data: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_u_package_data: registering package: OK")
    u_package_data["base_package"] = response.json["package"]["id"]
    LOGGER.debug("test_update_u_package_data: registering u_package")
    request_json = {"model_type": "u_package", "model": u_package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "u_package_created", response.json
    assert response.json["status"] == "success"
    assert "u_package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_u_package_data: registering u_package: OK")
    sample_update_u_package_data["id"] = response.json["u_package"]["id"]

    LOGGER.debug("test_update_u_package_data: registering second user")
    second_user_data = {"name": "ext_test_user2", "password_hash": make_password_ready("ext_test_user_password2")}
    request_json = {"model_type": "user", "model": second_user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_u_package_data: registering second user: OK")
    sample_update_u_package_data["user"] = response.json["user"]["id"]
    LOGGER.debug("test_update_u_package_data: updating u_package")

    LOGGER.debug("sample_update_u_package_data: %s", sample_update_u_package_data)
    request_json = {"model_type": "u_package", "model": sample_update_u_package_data}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "u_package_updated", response.json
    assert response.json["status"] == "success"
    assert "u_package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_u_package_data: updating u_package: OK")
    show_db_data(app_contx=app_ctx)


def test_update_package_with_package_content_data_without_package_content(
    client, package_data, admin_data_auth, sample_update_package_with_package_content_data, app_ctx
):
    # TODO: HATA? - olmayan package_content_id'leri olursa umursamıyor
    LOGGER.debug("test_update_package_with_package_content_data: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200

    sample_update_package_with_package_content_data["id"] = response.json["package"]["id"]
    LOGGER.debug("test_update_package_with_package_content_data: updating package")
    LOGGER.debug("sample_update_package_with_package_content_data: %s", sample_update_package_with_package_content_data)
    request_json = {"model_type": "package", "model": sample_update_package_with_package_content_data}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "package_updated", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_with_package_content_data: updating package: OK")
    show_db_data(app_contx=app_ctx)


def test_update_package_with_package_content_data_with_package_content(
    client, package_data, admin_data_auth, sample_update_package_with_package_content_data, random_package_content_data, app_ctx
):
    LOGGER.debug("test_update_package_with_package_content_data_with_package_content: registering package_content")
    request_json = {"model_type": "package_content", "model": random_package_content_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    name_package_contents = response.json["package_content"]["name"]

    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200

    package_data["package_contents"] = [response.json["package_content"]["id"]]
    LOGGER.debug("test_update_package_with_package_content_data_with_package_content: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200

    sample_update_package_with_package_content_data["id"] = response.json["package"]["id"]

    LOGGER.debug("test_update_package_with_package_content_data_with_package_content: adding second package_content")
    random_package_content_data["content_value"] = random.choice([pc for pc in pContentEnum if pc != name_package_contents])
    random_package_content_data["name"] = "extra_user" + random_package_content_data["content_value"]

    request_json = {"model_type": "package_content", "model": random_package_content_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)

    assert response.json["message"] == "package_content_created", response.json
    assert response.json["status"] == "success"
    assert "package_content" in response.json.keys()
    assert response.status_code == 200

    LOGGER.debug("test_update_package_with_package_content_data_with_package_content: updating package")
    LOGGER.debug("sample_update_package_with_package_content_data: %s", sample_update_package_with_package_content_data)
    request_json = {"model_type": "package", "model": sample_update_package_with_package_content_data}
    response = client.put(URLS.AUpdate, json=request_json, content_type="application/json", auth=admin_data_auth)

    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "package_updated", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_with_package_content_data_with_package_content: updating package: OK")
    show_db_data(app_contx=app_ctx)


def test_register_user_package(client, user_data_auth, user_data, package_data, admin_data_auth):
    LOGGER.debug("test_register_user_package: registering user")
    request_json = {"model_type": "user", "model": user_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "user_created", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user_package: registering user: OK")

    LOGGER.debug("test_register_user_package: registering package")
    request_json = {"model_type": "package", "model": package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user_package: registering package: OK")

    LOGGER.debug("test_register_user_package: registering user_package")
    user_package_data = {"user": response.json["user"]["id"], "base_package": response.json["package"]["id"]}
    request_json = {"model_type": "u_package", "model": user_package_data}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "u_package_created", response.json
    assert response.json["status"] == "success"
    assert "u_package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_register_user_package: registering user_package: OK")


def test_register_package_with_contents(client, package_data_with_random_content_datas, admin_data_auth):
    LOGGER.debug("test_register_package_with_contents: registering package")
    request_json = {"model_type": "package", "model": package_data_with_random_content_datas}
    response = client.post(URLS.ARegister, json=request_json, content_type="application/json", auth=admin_data_auth)
    LOGGER.debug("response: %s", response)
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "package_created", response.json
    assert response.json["status"] == "success"
    assert "package" in response.json.keys()
    assert "package_contents" in response.json["package"].keys()
    assert package_data_with_random_content_datas["package_contents"] == response.json["package"]["package_contents"]
    assert response.status_code == 200
    LOGGER.debug("test_register_package_with_contents: registering package: OK")


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_app.py"])
