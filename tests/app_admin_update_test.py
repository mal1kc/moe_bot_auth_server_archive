from moe_gthr_auth_server.enums import mType

from tests.testing_helpers import show_db_data, LOGGER, URLS

# from moe_gthr_auth_server.database_ops import pContentEnum, utc_timestamp
# from moe_gthr_auth_server.crpytion import make_password_ready


def test_update_user_data(
    client, user_from_db, update_sample_user_data, admin_data_auth, app_contx
):
    LOGGER.debug("user_from_db: %s", user_from_db)
    LOGGER.debug("update_sample_user_data: %s", update_sample_user_data)
    user_id = user_from_db.id

    # update user data
    request_json = {
        "new_model": {
            **update_sample_user_data,
        }
    }

    response = client.put(
        URLS.AUpdate.format(m_type=mType.user, m_id=user_id),
        json=request_json,
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "user_updated", response.json
    assert response.json["status"] == "success", response.json
    assert "user" in response.json.keys()
    assert response.status_code == 200
    show_db_data(app_contx)
    LOGGER.debug("test_update_user_data: OK")


def test_update_user_data_invalid_or_empty(
    client, user_from_db, update_sample_user_data, admin_data_auth
):
    LOGGER.debug("test_update_user_data_invalid_or_empty")
    LOGGER.debug("user_from_db: %s", user_from_db)
    LOGGER.debug("update_sample_user_data: %s", update_sample_user_data)
    user_id = user_from_db.id

    # update user data with invalid data
    update_sample_user_data["name"] = ""
    request_json = {
        "new_model": {
            **update_sample_user_data,
        }
    }
    repsonse = client.put(
        URLS.AUpdate.format(m_type=mType.user, m_id=user_id),
        json=request_json,
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", repsonse)
    assert repsonse.json["message"] == "bad_request", repsonse.json
    assert repsonse.json["status"] == "error", repsonse.json
    assert repsonse.json["error"] == "not_valid_name", repsonse.json
    assert repsonse.status_code == 400


def test_update_package_data(
    client,
    package_from_db,
    random_package_contents_from_db,
    update_sample_package_data,
    admin_data_auth,
):
    LOGGER.debug("test_update_package_data")
    LOGGER.debug("package_from_db: %s", package_from_db)
    LOGGER.debug("update_sample_package_data: %s", update_sample_package_data)
    package_id = package_from_db.id
    update_sample_package_data["package_contents"] = [
        pc.id for pc in random_package_contents_from_db
    ]
    # update package data
    request_json = {
        "new_model": {
            **update_sample_package_data,
        }
    }
    response = client.put(
        URLS.AUpdate.format(m_type=mType.package, m_id=package_id),
        json=request_json,
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "package_updated", response.json
    assert response.json["status"] == "success", response.json
    assert "package" in response.json.keys()
    assert response.status_code == 200


def test_update_package_data_invalid_or_empty(
    client,
    package_from_db,
    random_package_contents_from_db,
    update_sample_package_data,
    admin_data_auth,
):
    LOGGER.debug("test_update_package_data_invalid_or_empty")
    LOGGER.debug("package_from_db: %s", package_from_db)
    LOGGER.debug("update_sample_package_data: %s", update_sample_package_data)
    package_id = package_from_db.id
    update_sample_package_data["package_contents"] = [
        pc.id for pc in random_package_contents_from_db
    ]
    update_sample_package_data["name"] = ""
    request_json = {
        "new_model": {
            **update_sample_package_data,
        }
    }
    response = client.put(
        URLS.AUpdate.format(m_type=mType.package, m_id=package_id),
        json=request_json,
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "package_updated", response.json
    assert response.json["status"] == "success", response.json
    assert "package" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_data_invalid_or_empty: OK")


def test_update_package_data_invalid_package_contents(
    client,
    package_from_db,
    random_package_contents_from_db,
    update_sample_package_data,
    admin_data_auth,
):
    LOGGER.debug("test_update_package_data_invalid_package_contents")
    LOGGER.debug("package_from_db: %s", package_from_db)
    LOGGER.debug("update_sample_package_data: %s", update_sample_package_data)
    package_id = package_from_db.id
    update_sample_package_data["package_contents"] = [
        pc.id for pc in random_package_contents_from_db
    ]
    update_sample_package_data["package_contents"].append(9999999999999999999999999)
    request_json = {
        "new_model": {
            **update_sample_package_data,
        }
    }
    response = client.put(
        URLS.AUpdate.format(m_type=mType.package, m_id=package_id),
        json=request_json,
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "bad_request", response.json
    assert response.json["status"] == "error", response.json
    assert response.json["error"] == "not_valid_package_contents", response.json
    assert response.status_code == 400
    LOGGER.debug("test_update_package_data_invalid_package_contents: OK")


def test_update_package_content_data(
    client,
    random_package_content_from_db,
    update_sample_package_content_data,
    admin_data_auth,
):
    LOGGER.debug("test_update_package_content_data")
    LOGGER.debug("package_content_from_db: %s", random_package_content_from_db)
    LOGGER.debug(
        "update_sample_package_content_data: %s", update_sample_package_content_data
    )
    package_content_id = random_package_content_from_db.id
    request_json = {
        "new_model": {
            **update_sample_package_content_data,
        }
    }
    response = client.put(
        URLS.AUpdate.format(m_type=mType.package_content, m_id=package_content_id),
        json=request_json,
        auth=admin_data_auth,
    )
    LOGGER.debug("response: %s", response)
    assert response.json["message"] == "package_content_updated", response.json
    assert response.json["status"] == "success", response.json
    assert "package_content" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_update_package_content_data: OK")


def test_update_u_package_data():
    raise NotImplementedError


def test_update_package_with_package_content_data_without_package_content():
    raise NotImplementedError


def test_update_package_with_package_content_data_with_package_content():
    raise NotImplementedError
