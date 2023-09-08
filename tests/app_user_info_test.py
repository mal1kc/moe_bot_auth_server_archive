# user can get his/her own information
# user can get
# - u_package info # TODO get route for UINFO/mType.u_package
# - u_session info # TODO get route for UINFO/mType.u_session
# - self info # TODO get route for UINFO/mType.user
from tests.testing_helpers import LOGGER, URLS


def test_user_info(
    client,
    user_with_package_and_session_from_db,
    user_data_auth,
):
    LOGGER.info("test_user_info")
    user_id = user_with_package_and_session_from_db.id
    LOGGER.info(f"test_user_info: {user_with_package_and_session_from_db=}")
    LOGGER.info(f"test_user_info: {user_id=}")
    LOGGER.info(f"test_user_info: {URLS.UInfo=}")
    response = client.get(
        URLS.UInfo,
        auth=user_data_auth,
    )
    LOGGER.info(f"test_user_info: {response.json=}")
    assert response.json["status"] == "success", response.json
    assert response.json["message"] == "user_info_success", response.json
    assert "user" in response.json, response.json
    assert "package" in response.json["user"]
    assert response.status_code == 200
