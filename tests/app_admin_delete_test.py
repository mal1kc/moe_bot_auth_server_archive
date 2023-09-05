from tests.testing_helpers import LOGGER, URLS, mType


def test_delete_user(client, user_from_db, admin_data_auth):
    LOGGER.debug("test_delete_user: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.user, m_id=user_from_db.id), auth=admin_data_auth
    )
    assert response.json["status"] == "success"
    assert response.json["message"] == "user_deleted"
    # check if user is in response
    # -> recreate after false deletion by admin can be donable
    assert "user" in response.json
    assert response.json["user"]["id"] == user_from_db.id
    assert response.status_code == 200
    LOGGER.debug("test_delete_user: user deleted OK")
    LOGGER.debug("test_delete_user: sending info request")
    response = client.get(
        URLS.AInfo.format(m_type=mType.user, m_id=user_from_db.id), auth=admin_data_auth
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "user_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_user: user not found OK")


def test_delete_user_not_found(client, admin_data_auth):
    LOGGER.debug("test_delete_user_not_found: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.user, m_id=0), auth=admin_data_auth
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "user_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_user_not_found: user not found OK")


def test_delete_package_content(client, random_package_content_from_db, admin_data_auth):
    LOGGER.debug("test_delete_package_content: sending delete request")
    response = client.delete(
        URLS.ADelete.format(
            m_type=mType.package_content, m_id=random_package_content_from_db.id
        ),
        auth=admin_data_auth,
    )
    assert response.json["status"] == "success"
    assert response.json["message"] == "package_content_deleted"
    # check if package_content is in response
    # -> recreate after false deletion by admin can be donable
    assert "package_content" in response.json
    assert response.json["package_content"]["id"] == random_package_content_from_db.id
    assert response.status_code == 200
    LOGGER.debug("test_delete_package_content: package_content deleted OK")
    LOGGER.debug("test_delete_package_content: sending info request")
    response = client.get(
        URLS.AInfo.format(
            m_type=mType.package_content, m_id=random_package_content_from_db.id
        ),
        auth=admin_data_auth,
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "package_content_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_package_content: package_content not found OK")


def test_delete_package_content_not_found(client, admin_data_auth):
    LOGGER.debug("test_delete_package_content_not_found: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.package_content, m_id=0), auth=admin_data_auth
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "package_content_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_package_content_not_found: package_content not found OK")


def test_delete_package(client, package_from_db, admin_data_auth):
    LOGGER.debug("test_delete_package: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.package, m_id=package_from_db.id),
        auth=admin_data_auth,
    )
    assert response.json["status"] == "success"
    assert response.json["message"] == "package_deleted"
    # check if package is in response
    # -> recreate after false deletion by admin can be donable
    assert "package" in response.json
    assert response.json["package"]["id"] == package_from_db.id
    assert response.status_code == 200
    LOGGER.debug("test_delete_package: package deleted OK")
    LOGGER.debug("test_delete_package: sending info request")
    response = client.get(
        URLS.AInfo.format(m_type=mType.package, m_id=package_from_db.id),
        auth=admin_data_auth,
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "package_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_package: package not found OK")


def test_delete_package_not_found(client, admin_data_auth):
    LOGGER.debug("test_delete_package_not_found: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.package, m_id=0), auth=admin_data_auth
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "package_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_package_not_found: package not found OK")


def test_delete_u_package(client, u_package_from_db, admin_data_auth):
    LOGGER.debug("test_delete_u_package: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.u_package, m_id=u_package_from_db.id),
        auth=admin_data_auth,
    )
    assert response.json["status"] == "success"
    assert response.json["message"] == "u_package_deleted"
    # check if u_package is in response
    # -> recreate after false deletion by admin can be donable
    assert "u_package" in response.json
    assert response.json["u_package"]["id"] == u_package_from_db.id
    assert response.status_code == 200
    LOGGER.debug("test_delete_u_package: u_package deleted OK")
    LOGGER.debug("test_delete_u_package: sending info request")
    response = client.get(
        URLS.AInfo.format(m_type=mType.u_package, m_id=u_package_from_db.id),
        auth=admin_data_auth,
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "u_package_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_u_package: u_package not found OK")


def test_delete_u_package_not_found(client, admin_data_auth):
    LOGGER.debug("test_delete_u_package_not_found: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.u_package, m_id=0), auth=admin_data_auth
    )
    assert response.json["status"] == "error"
    assert response.json["message"] == "u_package_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_u_package_not_found: u_package not found OK")


def test_delete_user_with_package(client, user_with_package_from_db, admin_data_auth):
    u_package_id = user_with_package_from_db.package.id
    LOGGER.debug("test_delete_user_with_package: sending delete request")
    response = client.delete(
        URLS.ADelete.format(m_type=mType.user, m_id=user_with_package_from_db.id),
        auth=admin_data_auth,
    )
    assert response.json["status"] == "success", response.json
    assert response.json["message"] == "user_deleted"
    # check if user is in response
    # -> recreate after false deletion by admin can be donable
    assert "user" in response.json
    assert response.json["user"]["id"] == user_with_package_from_db.id
    assert response.status_code == 200
    LOGGER.debug("test_delete_user_with_package: user deleted OK")
    LOGGER.debug("test_delete_user_with_package: sending info request for package")
    response = client.get(
        URLS.AInfo.format(m_type=mType.u_package, m_id=u_package_id), auth=admin_data_auth
    )
    LOGGER.debug("test_delete_user_with_package: response: %s", response.json)
    assert response.json["status"] == "error"
    assert response.json["message"] == "u_package_not_found"
    assert response.status_code == 404
    LOGGER.debug("test_delete_user_with_package: package not found OK")
