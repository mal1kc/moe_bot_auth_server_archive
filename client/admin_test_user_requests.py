import sys
import logging
from client.admin_requests import (
    register_user,
    register_package,
    register_user_package,
)
from client.utils import LOGGER


def main():
    test_user_without_package_data = {
        "name": "test_user_without_package",
        "password_hash": "test_user_without_package",  # this will be hashed and encrypted in the register_user function # noqa
    }
    test_user_with_package_data = {
        "name": "test_user_with_package",
        "password_hash": "test_user_with_package",  # this will be hashed and encrypted in the register_user function # noqa
    }
    test_package_data = {
        "name": "test_package",
        "detail": "test_package_detail",
        "days": 30,
    }
    # test_package_content_data = {
    # "name": "test_package_content", "content_value": "moe_gatherer"
    # }
    # # we use the initialized ones id
    test_u_package_data = {
        # "start_date": 1680489600, # 2023-04-01 00:00:00 UTC +0
        # / this will be set in the register_user_package function as ytcnow() # noqa
        "user": 1,
        "base_package": 1,
    }

    LOGGER.info("Registering user without package")

    register_result, is_ok = register_user(
        name=test_user_without_package_data["name"],
        password=test_user_without_package_data["password_hash"],
    )

    LOGGER.info(f"Register result: {register_result}")
    LOGGER.info(f"Register is_ok: {is_ok}")

    LOGGER.info("Registering user with package")

    register_result, is_ok = register_user(
        name=test_user_with_package_data["name"],
        password=test_user_with_package_data["password_hash"],
    )

    LOGGER.info(f"Register result: {register_result}")

    LOGGER.info(f"Register is_ok: {is_ok}")

    if is_ok:
        test_u_package_data["user"] = register_result["user"]["id"]

    LOGGER.info("Registering package")

    register_result, is_ok = register_package(
        name=test_package_data["name"],
        detail=test_package_data["detail"],
        days=test_package_data["days"],
        package_contents=[1, 4, 6],
    )

    LOGGER.info(f"Register result: {register_result}")

    LOGGER.info(f"Register is_ok: {is_ok}")

    if is_ok:
        test_u_package_data["base_package"] = register_result["package"]["id"]

    LOGGER.info("Registering user package")

    register_result, is_ok = register_user_package(
        user_id=test_u_package_data["user"],
        package_id=test_u_package_data["base_package"],
    )

    LOGGER.info(f"Register result: {register_result}")

    LOGGER.info(f"Register is_ok: {is_ok}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "debug":
            LOGGER.setLevel(logging.DEBUG)
    main()