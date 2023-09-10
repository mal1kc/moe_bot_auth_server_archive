import logging
import sys
from typing import Any

import requests  # noqa

from client.data import mTypes, sample_user_data
from client.encryption import make_password_ready
from client.endpoints import EndPoints
from client.utils import LOGGER, admin_header_kwargs


def register_user(
    name: str = "ext_test_user",
) -> tuple[dict[str, Any], bool]:
    user_data = sample_user_data.copy()
    user_data["name"] = name
    user_data["password_hash"] = make_password_ready(name)
    request_json = {
        "model": user_data,
    }
    LOGGER.debug(
        f"registerinng user headers: {admin_header_kwargs}, url: {EndPoints.ARegister.format(m_type=mTypes.user)}, json: {request_json}"  # noqa
    )

    response = requests.post(
        EndPoints.ARegister.format(m_type=mTypes.user),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


def login_user(
    name: str = "ext_test_user",
    ready_password: str = make_password_ready("ext_test_user"),
):
    "probably fail because of user has no package"
    response = requests.post(EndPoints.ULogin, auth=(name, ready_password))

    return response.json(), response.ok


def get_user_info():
    response = requests.get(
        EndPoints.UInfo,
        auth=(sample_user_data["name"], make_password_ready("ext_test_user")),
    )
    return response.json()


def main():
    """This is a main function"""

    LOGGER.info("Starting user_requests.py")
    LOGGER.info("Registering user")
    register_result, is_ok = register_user()
    LOGGER.info(f"Register result: {register_result}")
    LOGGER.info(f"Register is_ok: {is_ok}")
    LOGGER.info("Logging in user")
    login_result, is_ok = login_user()
    LOGGER.info(f"Login result: {login_result}")
    LOGGER.info(f"Login is_ok: {is_ok}")
    LOGGER.info("Getting user info")
    user_info = get_user_info()
    LOGGER.info(f"User info: {user_info}")
    LOGGER.info("Finished user_requests.py")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--info":
            LOGGER.setLevel(logging.INFO)
        elif sys.argv[1] == "--debug":
            LOGGER.setLevel(logging.DEBUG)
    main()
