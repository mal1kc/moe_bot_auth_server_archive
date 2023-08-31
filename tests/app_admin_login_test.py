from tests.testing_helpers import URLS


def test_admin_login(client, app_db_add_users, admin_data_auth):
    if not app_db_add_users:
        assert False, "Failed to add users"
    response = client.post(URLS.ALogin, auth=admin_data_auth)
    assert response.json["status"] == "success"
    assert "users" in response.json
    assert response.status_code == 200
