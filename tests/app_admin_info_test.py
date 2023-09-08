from tests.testing_helpers import LOGGER, URLS, mType


def test_info_user(
    client,
    user_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_user")
    response = client.get(
        URLS.AInfo.format(m_type=mType.user, m_id=user_from_db.id),
        auth=admin_data_auth,
    )
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "success", response.json
    assert response.json["user"]["id"] == user_from_db.id, response.json
    assert response.status_code == 200


def test_info_user_fail(
    client,
    user_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_user_fail")
    response = client.get(
        URLS.AInfo.format(m_type=mType.user, m_id=user_from_db.id + 1),
        auth=admin_data_auth,
    )
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["status"] == "error"
    assert response.json["message"] == "user_not_found", response.json
    assert response.status_code == 404


def test_info_package(
    client,
    package_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_package")
    response = client.get(
        URLS.AInfo.format(m_type=mType.package, m_id=package_from_db.id),
        auth=admin_data_auth,
    )
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "success", response.json
    assert response.json["package"]["id"] == package_from_db.id, response.json
    assert response.status_code == 200


def test_info_package_not_found(
    client,
    package_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_package_not_found")
    response = client.get(
        URLS.AInfo.format(m_type=mType.package, m_id=package_from_db.id + 1),
        auth=admin_data_auth,
    )
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["status"] == "error"
    assert response.json["message"] == "package_not_found", response.json
    assert response.status_code == 404


def test_info_package_content(
    client,
    random_package_content_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_package_content")
    response = client.get(
        URLS.AInfo.format(
            m_type=mType.package_content, m_id=random_package_content_from_db.id
        ),
        auth=admin_data_auth,
    )
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "success", response.json
    assert (
        response.json["package_content"]["id"] == random_package_content_from_db.id
    ), response.json
    assert response.status_code == 200


def test_info_package_content_not_found(
    client,
    random_package_content_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_package_content_not_found")
    response = client.get(
        URLS.AInfo.format(
            m_type=mType.package_content, m_id=random_package_content_from_db.id + 1
        ),
        auth=admin_data_auth,
    )
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["status"] == "error"
    assert response.json["message"] == "package_content_not_found", response.json
    assert response.status_code == 404


def test_info_package_with_random_contents_from_db(
    client,
    package_with_random_contents_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_package_with_random_contents_from_db")
    response = client.get(
        URLS.AInfo.format(
            m_type=mType.package, m_id=package_with_random_contents_from_db.id
        ),
        auth=admin_data_auth,
    )
    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "success", response.json
    assert (
        response.json["package"]["id"] == package_with_random_contents_from_db.id
    ), response.json
    assert response.status_code == 200
    assert len(response.json["package"]["package_contents"]) == len(
        package_with_random_contents_from_db.package_contents
    ), response.json


def test_info_u_package(
    client,
    u_package_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_u_package")
    response = client.get(
        URLS.AInfo.format(m_type=mType.u_package, m_id=u_package_from_db.id),
        auth=admin_data_auth,
    )

    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "success", response.json
    assert response.json["u_package"]["id"] == u_package_from_db.id, response.json
    assert response.status_code == 200


def test_info_u_package_not_found(
    client,
    u_package_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_u_package_not_found")
    response = client.get(
        URLS.AInfo.format(m_type=mType.u_package, m_id=u_package_from_db.id + 1),
        auth=admin_data_auth,
    )

    LOGGER.debug("response.json: %s", response.json)
    assert response.json["status"] == "error"
    assert response.json["message"] == "u_package_not_found", response.json
    assert response.status_code == 404


def test_info_user_with_package_and_session(
    client,
    user_with_package_and_session_from_db,
    admin_data_auth,
):
    LOGGER.debug("test_info_user_with_package_and_session_from_db")
    response = client.get(
        URLS.AInfo.format(m_type=mType.user, m_id=user_with_package_and_session_from_db.id),
        auth=admin_data_auth,
    )

    LOGGER.debug("response.json: %s", response.json)
    assert response.json["message"] == "success", response.json
    assert (
        response.json["user"]["id"] == user_with_package_and_session_from_db.id
    ), response.json
    assert response.status_code == 200
    assert response.json["user"][
        "package"
    ] == user_with_package_and_session_from_db.package.__json__(
        user_incld=False
    ), user_with_package_and_session_from_db.package.__json__()
    assert response.json["user"]["sessions"] == [
        session.__json__() for session in user_with_package_and_session_from_db.sessions
    ], response.json
