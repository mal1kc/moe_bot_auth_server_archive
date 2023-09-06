# ruff: noqa: E501
import datetime
import logging
import time
from typing import Any

import requests

from data import (
    mTypes,
    pContentEnum,
    sample_package_content_data,
    sample_package_data,
    sample_user_data,
)
from encryption import make_password_ready
from endpoints import EndPoints
from utils import (
    admin_header_kwargs,
    requests_session,
    took_time_decorator_ns,
    generate_random_sized_random_int_list,
)
from user_requests import login_user

LOGGER = logging.getLogger(__name__)


def main():
    # tests registers and user login
    # not too rondom ehehehe
    req_session = requests_session
    random_user_name = f"ext_test_user_{time.time_ns()}"
    random_package_name = f"ext_test_package_{time.time_ns()}"
    random_content_values = generate_random_sized_random_int_list(
        max_int=len(list(pContentEnum))
    )
    # this enum is already created in the database with initdb command
    response_register_user = register_user(name=random_user_name)
    response_register_user_dict = response_register_user[0]
    if not response_register_user[1]:
        LOGGER.error(f"register user failed {response_register_user_dict}")
        return
    LOGGER.info("register user success")
    LOGGER.debug(f"response_register_user_dict: {response_register_user_dict}")
    response_register_package = register_package(
        name=random_package_name,
        # needs to be id or new package content object
        #  [ 1 ,2 ,3 ,4, 5, 6 ]
        #  or [{ "name": "ext_test_package_content", "content_value": pContentEnum.??? }, ...]
        package_contents=random_content_values,
        request_session=req_session,
    )  # type: ignore
    response_register_package_dict = response_register_package[0]
    if not response_register_package[1]:
        LOGGER.error(f"register package failed: {response_register_package_dict}")
        return
    LOGGER.info("register package success")
    LOGGER.debug(f"response_register_package_dict: {response_register_package_dict}")
    LOGGER.info("registering package contents")
    response_register_user_package = register_user_package(
        user_id=response_register_user_dict["user"]["id"],
        package_id=response_register_package_dict["package"]["id"],
        request_session=req_session,
    )
    if not response_register_user_package[1]:
        LOGGER.error(f"register user_package failed: { response_register_user_package}")
        return
    LOGGER.info("register user_package success")
    LOGGER.debug(f"response_register_user_package: {response_register_user_package}")
    response_login_user = login_user(
        name=random_user_name,
        ready_password=make_password_ready(random_user_name),
        request_session=req_session,
    )
    if not response_login_user[1]:
        LOGGER.error(f"login user failed: {response_login_user}")
        return
    LOGGER.info("login user success")
    LOGGER.debug(f"response_login_user: {response_login_user}")
    req_session.close()


@took_time_decorator_ns
def register_user(name: str = "ext_test_user") -> tuple[dict[str, Any], bool]:
    user_data = sample_user_data.copy()
    user_data["name"] = name
    user_data["password_hash"] = make_password_ready(name)
    request_json = {
        "model": user_data,
    }
    LOGGER.debug(
        f"registerinng user headers: {admin_header_kwargs}, url: {EndPoints.ARegister.format(m_type=mTypes.user)}, json: {request_json}"
    )

    response = requests_session.post(
        EndPoints.ARegister.format(m_type=mTypes.user),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def register_package(
    package_contents: list[int] | None = None,
    name: str = "ext_test_package",
    detail: str = "ext_test_package_detail",
    days: int = 30,
    request_session: requests.Session = requests_session,
) -> tuple[dict[str, Any], bool]:
    package_data = sample_package_data.copy()
    package_data["name"] = name
    package_data["detail"] = detail
    package_data["days"] = days
    if package_contents is not None:
        for package_content in package_contents:
            if package_content not in package_data["package_contents"] and isinstance(
                package_content, int
            ):
                package_data["package_contents"].append(package_content)
    request_json = {
        "model": package_data,
    }
    LOGGER.info(
        f"registerinng package headers: {admin_header_kwargs}, url: {EndPoints.ARegister.format(m_type=mTypes.package)}, json: {request_json}"
    )
    response = request_session.post(
        EndPoints.ARegister.format(m_type=mTypes.package),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def register_package_content(
    name: str = "ext_test_package_content",
    content_value: pContentEnum = pContentEnum.moe_gatherer,
) -> tuple[dict[str, Any], bool]:
    package_content_data = sample_package_content_data.copy()
    package_content_data["name"] = name
    package_content_data["content_value"] = content_value
    request_json = {
        "model": package_content_data,
    }
    LOGGER.debug(
        f"registerinng package_content headers: {admin_header_kwargs}, url: {EndPoints.ARegister.format(m_type=mTypes.package_content)}, json: {request_json}"
    )
    response = requests_session.post(
        EndPoints.ARegister.format(m_type=mTypes.package_content),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def register_user_package(
    user_id: int = 1,
    package_id: int = 1,
    request_session: requests.Session = requests_session,
) -> tuple[dict[str, Any], bool]:
    u_package_data = {
        "start_date": int(
            datetime.datetime.utcnow().timestamp()
        ),  # IMPORTANT: this is in UTC and is int not float
        "user": user_id,
        "base_package": package_id,
    }
    request_json = {
        "model": u_package_data,
    }
    LOGGER.debug(
        f"registerinng user_package headers: {admin_header_kwargs}, url: {EndPoints.ARegister.format(m_type=mTypes.u_package)}, json: {request_json}"
    )
    response = request_session.post(
        EndPoints.ARegister.format(m_type=mTypes.u_package),
        json=request_json,
        **admin_header_kwargs,
    )

    return response.json(), response.ok


if __name__ == "__main__":
    main()
    # response = register_package(
    #     package_contents=generate_random_sized_random_package_content_list(),
    #     name="ext_test_package",
    #     detail="ext_test_package_detail",
    #     days=30,
    #     request_session=requests_session,
    # )[0]
    # print(response)
