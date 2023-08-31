import pytest
import random
import datetime

from tests.testing_helpers import show_db_data, LOGGER, URLS
from moe_gthr_auth_server.database_ops import pContentEnum, utc_timestamp
from moe_gthr_auth_server.crpytion import make_password_ready


@pytest.fixture
def sample_update_user_data() -> dict:
    return {"id": None, "name": "ext_test_user_updated", "password_hash": make_password_ready("ext_test_user_password_updated")}


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


def test_update_user_data_invalid_or_empty(client, user_data, admin_data_auth, sample_update_user_data):
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


@pytest.fixture
def sample_update_package_data() -> dict:
    return {"id": None, "name": "ext_test_package_updated", "detail": "ext_test_package_detail_updated", "days": 12}


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


def test_update_package_data_invalid_or_empty(client, package_data, admin_data_auth, sample_update_package_data):
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


def test_update_package_data_invalid_package_contents(client, package_data, admin_data_auth, sample_update_package_data):
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


@pytest.fixture
def sample_update_package_content_data() -> dict:
    return {"id": None, "name": "ext_test_package_content_updated", "content_value": "extra_user"}


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


@pytest.fixture
def sample_update_u_package_data() -> dict:
    return {"id": None, "user": 1, "base_package": 1, "start_date": utc_timestamp(datetime.datetime.utcnow())}


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


@pytest.fixture
def sample_update_package_with_package_content_data() -> dict:
    return {
        "id": None,
        "name": "ext_test_package_updated",
        "detail": "ext_test_package_detail_updated",
        "days": 12,
        "package_contents": [1, 2],
    }


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
