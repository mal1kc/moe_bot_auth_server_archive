# ruff: noqa: E501
import datetime
import logging
import sys
import time
from typing import Any

import requests
from user_requests import login_user

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
    generate_random_sized_random_int_list,
    took_time_decorator_ns,
)

LOGGER = logging.getLogger(__name__)


@took_time_decorator_ns
def register_user(
    name: str = "ext_test_user",
    password: str = "ext_test_user",
) -> tuple[dict[str, Any], bool]:
    user_data = sample_user_data.copy()
    user_data["name"] = name
    user_data["password_hash"] = make_password_ready(password)
    request_json = {
        "model": user_data,
    }
    LOGGER.debug(
        f"registerinng user headers: {admin_header_kwargs}, url: {EndPoints.ARegister.format(m_type=mTypes.user)}, json: {request_json}"
    )

    response = requests.post(
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
    response = requests.post(
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
    response = requests.post(
        EndPoints.ARegister.format(m_type=mTypes.package_content),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def register_user_package(
    user_id: int = 1,
    package_id: int = 1,
) -> tuple[dict[str, Any], bool]:
    u_package_data = {
        "start_date": int(
            datetime.datetime.now().timestamp()
        ),  # IMPORTANT: this is int not float
        "user": user_id,
        "base_package": package_id,
    }
    request_json = {
        "model": u_package_data,
    }
    LOGGER.debug(
        f"registerinng user_package headers: {admin_header_kwargs}, url: {EndPoints.ARegister.format(m_type=mTypes.u_package)}, json: {request_json}"
    )
    response = requests.post(
        EndPoints.ARegister.format(m_type=mTypes.u_package),
        json=request_json,
        **admin_header_kwargs,
    )

    return response.json(), response.ok


@took_time_decorator_ns
def update_user(
    user_id: int = 1,
    name: str = "ext_test_user",
) -> tuple[dict[str, Any], bool]:
    user_data = sample_user_data.copy()
    user_data["name"] = name
    user_data["password_hash"] = make_password_ready(name)
    request_json = {
        "new_model": user_data,
    }
    LOGGER.debug(
        f"registerinng user headers: {admin_header_kwargs}, url: {EndPoints.AUpdate.format(m_type=mTypes.user, m_id=user_id)}, json: {request_json}"
    )

    response = requests.put(
        EndPoints.AUpdate.format(m_type=mTypes.user, m_id=user_id),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def update_package(
    package_id: int = 1,
    package_contents: list[int] | None = None,
    name: str = "ext_test_package",
    detail: str = "ext_test_package_detail",
    days: int = 30,
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
        "new_model": package_data,
    }
    LOGGER.info(
        f"registerinng package headers: {admin_header_kwargs}, url: {EndPoints.AUpdate.format(m_type=mTypes.package, m_id=package_id)}, json: {request_json}"
    )
    response = requests.put(
        EndPoints.AUpdate.format(m_type=mTypes.package, m_id=package_id),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def update_package_content(
    package_content_id: int = 1,
    name: str = "ext_test_package_content",
    content_value: pContentEnum = pContentEnum.moe_gatherer,
) -> tuple[dict[str, Any], bool]:
    package_content_data = sample_package_content_data.copy()
    package_content_data["name"] = name
    package_content_data["content_value"] = content_value
    request_json = {
        "new_model": package_content_data,
    }
    LOGGER.debug(
        f"registerinng package_content headers: {admin_header_kwargs}, url: {EndPoints.AUpdate.format(m_type=mTypes.package_content, m_id=package_content_id)}, json: {request_json}"
    )
    response = requests.put(
        EndPoints.AUpdate.format(m_type=mTypes.package_content, m_id=package_content_id),
        json=request_json,
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def update_user_package(
    user_package_id: int = 1,
    user_id: int = 1,
    package_id: int = 1,
) -> tuple[dict[str, Any], bool]:
    u_package_data = {
        "start_date": int(
            datetime.datetime.now().timestamp()
        ),  # IMPORTANT: this is int not float
        "user": user_id,
        "base_package": package_id,
    }
    request_json = {
        "new_model": u_package_data,
    }
    LOGGER.debug(
        f"registerinng user_package headers: {admin_header_kwargs}, url: {EndPoints.AUpdate.format(m_type=mTypes.u_package, m_id=user_package_id)}, json: {request_json}"
    )
    response = requests.put(
        EndPoints.AUpdate.format(m_type=mTypes.u_package, m_id=user_package_id),
        json=request_json,
        **admin_header_kwargs,
    )

    return response.json(), response.ok


@took_time_decorator_ns
def get_info(m_type, m_id, admin_header_kwargs):
    response = requests.get(
        EndPoints.AInfo.format(m_type=m_type, m_id=m_id),
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def delete_model(m_type, m_id, admin_header_kwargs):
    response = requests.delete(
        EndPoints.ADelete.format(m_type=m_type, m_id=m_id),
        **admin_header_kwargs,
    )
    return response.json(), response.ok


@took_time_decorator_ns
def test_everything():
    """
    tests all admin endpoints and user login endpoint
    tests
    admin -> registers user, package, package_content, user_package
    admin -> gets user info, package info, package_content info, user_package info
    user -> login
    admin -> updates user, package, package_content, user_package
    admin -> gets user info, package info, package_content info, user_package info
    admin -> compare infos with previous infos (before update) # TODO not implemented
    admin -> deletes user_package, package, user
    """

    # not too rondom eheheheh
    LOGGER.info("=" * 20 + "making random data phase" + "=" * 20)
    random_user_name = f"ext_test_user_{time.time_ns()}"
    random_package_name = f"ext_test_package_{time.time_ns()}"
    random_content_value_ids = generate_random_sized_random_int_list(
        max_int=len(list(pContentEnum))
    )

    # this enum is already created in the database with initdb command
    LOGGER.info("=" * 20 + "register phase" + "=" * 20)
    response_register_user = register_user(name=random_user_name)
    response_register_user_dict = response_register_user[0]
    if not response_register_user[1]:
        LOGGER.error(f"register user failed {response_register_user_dict}")
        return
    LOGGER.info("register user success")
    LOGGER.debug(f"response_register_user_dict: {response_register_user_dict}")
    LOGGER.info("registering package contents")
    # register one of each content_value
    for content_value in pContentEnum:
        response_register_package_content = register_package_content(
            name=f"{random_package_name}_{content_value.name}",
            content_value=content_value,
        )
        if not response_register_package_content[1]:
            LOGGER.error(
                f"register package_content failed: {response_register_package_content}"
            )
            return
        LOGGER.info("register package_content success")
        LOGGER.debug(
            f"response_register_package_content: {response_register_package_content}"
        )
    response_register_package = register_package(
        name=random_package_name,
        # needs to be id or new package content object
        #  [ 1 ,2 ,3 ,4, 5, 6 ]
        #  or [{ "name": "ext_test_package_content", "content_value": pContentEnum.??? }, ...]
        package_contents=random_content_value_ids,
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
    )
    if not response_register_user_package[1]:
        LOGGER.error(f"register user_package failed: { response_register_user_package}")
        return
    LOGGER.info("register user_package success")
    LOGGER.debug(f"response_register_user_package: {response_register_user_package}")

    LOGGER.info("=" * 20 + "login phase" + "=" * 20)
    response_login_user = login_user(
        name=random_user_name,
        ready_password=make_password_ready(random_user_name),
    )
    if not response_login_user[1]:
        LOGGER.error(f"login user failed: {response_login_user}")
        return
    LOGGER.info("login user success")

    LOGGER.debug(f"response_login_user: {response_login_user}")

    LOGGER.info("=" * 20 + "get info phase" + "=" * 20)
    LOGGER.info("getting user info")
    response_get_user_info = get_info(
        m_type=mTypes.user,
        m_id=response_register_user_dict["user"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_get_user_info[1]:
        LOGGER.error(f"get user info failed: {response_get_user_info}")
        return
    LOGGER.info("get user info success")
    LOGGER.debug(f"response_get_user_info: {response_get_user_info}")
    LOGGER.info("getting package info")
    response_get_package_info = get_info(
        m_type=mTypes.package,
        m_id=response_register_package_dict["package"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_get_package_info[1]:
        LOGGER.error(f"get package info failed: {response_get_package_info}")
        return
    LOGGER.info("get package info success")
    LOGGER.debug(f"response_get_package_info: {response_get_package_info}")
    LOGGER.info("getting package_content info")
    for package_content_id in random_content_value_ids:
        response_get_package_content_info = get_info(
            m_type=mTypes.package_content,
            m_id=package_content_id,
            admin_header_kwargs=admin_header_kwargs,
        )
        if not response_get_package_content_info[1]:
            LOGGER.error(
                f"get package_content info failed: {response_get_package_content_info}"
            )
            return
        LOGGER.info("get package_content info success")
        LOGGER.debug(
            f"response_get_package_content_info: {response_get_package_content_info}"
        )
    LOGGER.info("getting user_package info")
    response_get_user_package_info = get_info(
        m_type=mTypes.u_package,
        m_id=response_register_user_package[0]["u_package"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_get_user_package_info[1]:
        LOGGER.error(f"get user_package info failed: {response_get_user_package_info}")
        return
    LOGGER.info("get user_package info success")
    LOGGER.debug(f"response_get_user_package_info: {response_get_user_package_info}")

    LOGGER.info("=" * 20 + "update phase" + "=" * 20)
    LOGGER.info("updating user")
    response_update_user = update_user(
        user_id=response_register_user_dict["user"]["id"],
        name=f"{random_user_name}_updated",
    )
    if not response_update_user[1]:
        LOGGER.error(f"update user failed: {response_update_user}")
        return
    LOGGER.info("update user success")
    LOGGER.debug(f"response_update_user: {response_update_user}")
    LOGGER.info("updating package")
    response_update_package = update_package(
        package_id=response_register_package_dict["package"]["id"],
        name=f"{random_package_name}_updated",
        package_contents=generate_random_sized_random_int_list(
            max_int=len(list(pContentEnum))
        ),
    )
    if not response_update_package[1]:
        LOGGER.error(f"update package failed: {response_update_package}")
        return
    LOGGER.info("update package success")
    LOGGER.debug(f"response_update_package: {response_update_package}")
    # already created in initdb initial package contents, and can't be added new with accepted content_values
    # LOGGER.info("updating package_content")
    # for package_content_id in random_content_value_ids:
    #     response_update_package_content = update_package_content(
    #         package_content_id=package_content_id,
    #         name=f"{random_package_name}_updated",
    #         content_value=pContentEnum.extra_session,
    #     )
    #     if not response_update_package_content[1]:
    #         LOGGER.error(
    #             f"update package_content failed: {response_update_package_content}"
    #         )
    #         return
    #     LOGGER.info("update package_content success")
    #     LOGGER.debug(f"response_update_package_content: {response_update_package_content}")
    # LOGGER.info("updating user_package")
    response_update_user_package = update_user_package(
        user_package_id=response_register_user_package[0]["u_package"]["id"],
        user_id=response_register_user_dict["user"]["id"],
        package_id=response_register_package_dict["package"]["id"],
    )
    if not response_update_user_package[1]:
        LOGGER.error(f"update user_package failed: {response_update_user_package}")
        return
    LOGGER.info("update user_package success")
    LOGGER.debug(f"response_update_user_package: {response_update_user_package}")
    LOGGER.info("=" * 20 + "get info 2 phase" + "=" * 20)
    LOGGER.info("getting user info")
    response_get_user_info = get_info(
        m_type=mTypes.user,
        m_id=response_register_user_dict["user"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_get_user_info[1]:
        LOGGER.error(f"get user info failed: {response_get_user_info}")
        return
    LOGGER.info("get user info success")
    LOGGER.debug(f"response_get_user_info: {response_get_user_info}")
    LOGGER.info("getting package info")
    response_get_package_info = get_info(
        m_type=mTypes.package,
        m_id=response_register_package_dict["package"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_get_package_info[1]:
        LOGGER.error(f"get package info failed: {response_get_package_info}")
        return
    LOGGER.info("get package info success")
    LOGGER.debug(f"response_get_package_info: {response_get_package_info}")
    LOGGER.info("getting package_content info")
    for package_content_id in random_content_value_ids:
        response_get_package_content_info = get_info(
            m_type=mTypes.package_content,
            m_id=package_content_id,
            admin_header_kwargs=admin_header_kwargs,
        )
        if not response_get_package_content_info[1]:
            LOGGER.error(
                f"get package_content info failed: {response_get_package_content_info}"
            )
            return
        LOGGER.info("get package_content info success")
        LOGGER.debug(
            f"response_get_package_content_info: {response_get_package_content_info}"
        )
    LOGGER.info("getting user_package info")
    response_get_user_package_info = get_info(
        m_type=mTypes.u_package,
        m_id=response_register_user_package[0]["u_package"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_get_user_package_info[1]:
        LOGGER.error(f"get user_package info failed: {response_get_user_package_info}")
        return
    LOGGER.info("get user_package info success")
    LOGGER.debug(f"response_get_user_package_info: {response_get_user_package_info}")

    LOGGER.info(("=" * 20) + "deleting phase" + ("=" * 20))
    LOGGER.info("deleting user_package")
    response_delete_user_package = delete_model(
        m_type=mTypes.u_package,
        m_id=response_register_user_package[0]["u_package"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_delete_user_package[1]:
        LOGGER.error(f"delete user_package failed: {response_delete_user_package}")
        return
    LOGGER.info("delete user_package success")
    LOGGER.debug(f"response_delete_user_package: {response_delete_user_package}")
    LOGGER.info("deleting package")
    response_delete_package = delete_model(
        m_type=mTypes.package,
        m_id=response_register_package_dict["package"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_delete_package[1]:
        LOGGER.error(f"delete package failed: {response_delete_package}")
        return
    LOGGER.info("delete package success")
    LOGGER.debug(f"response_delete_package: {response_delete_package}")
    LOGGER.info("deleting user")
    response_delete_user = delete_model(
        m_type=mTypes.user,
        m_id=response_register_user_dict["user"]["id"],
        admin_header_kwargs=admin_header_kwargs,
    )
    if not response_delete_user[1]:
        LOGGER.error(f"delete user failed: {response_delete_user}")
        return
    LOGGER.info("delete user success")
    LOGGER.debug(f"response_delete_user: {response_delete_user}")
    LOGGER.info("=" * 20 + "end of test" + "=" * 20)
    LOGGER.info("=" * 20 + "everything succeed" + "=" * 20)


def main():
    test_everything()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--info":
            LOGGER.setLevel(logging.INFO)
        elif sys.argv[1] == "--debug":
            LOGGER.setLevel(logging.DEBUG)
    main()
    # response = requests.post(
    #     EndPoints.ALogin,
    #     **admin_header_kwargs,
    # )
    # print(response.json())
    # print(response)
