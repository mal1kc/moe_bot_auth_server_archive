from moe_gthr_auth_server.enums import mType
from tests.testing_helpers import URLS, LOGGER


def test_login_without_u_package(client, user_data_auth, user_data, admin_data_auth):
    LOGGER.debug("test_login: registering user")
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
    LOGGER.debug("test_login: registering user: OK")

    LOGGER.debug("test_login: logging in user")
    response = client.post(URLS.ULogin, auth=user_data_auth)
    assert response.json["message"] == "package_not_found", response.json
    assert response.json["status"] == "error"
    LOGGER.debug("test_login: logging in user: response_json %s", response.json)
    assert response.status_code == 404
    LOGGER.debug("test_login: logging in user: OK")


def test_login_with_u_package(
    client,
    user_data_auth,
    u_package_from_db,
):
    LOGGER.debug(
        "test_login_with_u_package: user pakcage from u_package %s", u_package_from_db
    )

    LOGGER.debug("test_login_with_u_package: logging in user")
    response = client.post(URLS.ULogin, auth=user_data_auth)
    assert response.json["message"] == "login_success", response.json
    assert response.json["status"] == "success"
    assert "user" in response.json.keys()
    assert response.status_code == 200
    LOGGER.debug("test_login_with_u_package: logging in user: OK")