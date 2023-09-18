def test_page_load(client):
    """Test that the index page loads."""
    response = client.get("/admin_control/index")
    assert response.status_code == 200
    assert b"Admin Control Panel" in response.data
