from moe_gthr_auth_server.cryption import (
    compare_encypted_hashes,
    make_password_hash,
    unmake_password_ready,
)
from tests.testing_helpers import LOGGER


def test_cryption(user_data):
    LOGGER.debug("test_cryption")
    assert unmake_password_ready(user_data["password_hash"]) == make_password_hash(
        "ext_test_user_password"
    )
    assert compare_encypted_hashes(
        user_data["password_hash"], make_password_hash("ext_test_user_password")
    )
    LOGGER.debug("test_cryption: OK")


def test_can_be_alive(client):
    LOGGER.debug("test_can_be_alive")
    assert client.get("/").status_code == 200
    LOGGER.debug("test_can_be_alive: OK")
