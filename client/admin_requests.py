import datetime
import random
from typing import Any

from client.analytics import took_time_decorator_ns
from encryption import make_password_ready  # noqa
from endpoints import EndPoints
from data import sample_admin_data, sample_user_data, sample_package_data, sample_package_content_data, pContentEnum  # type: ignore
import requests
import time

req_session = requests.Session()


def main():
    # tests registers and user login
    # not too rondom ehehehe
    random_user_name = f"ext_test_user_{time.time_ns()}"
    random_package_name = f"ext_test_package_{time.time_ns()}"
    random_package_content_name = f"ext_test_package_content_{time.time_ns()}"
    random_content_value = random.choice([pcontent for pcontent in pContentEnum])
    response_register_user = register_user(name=random_user_name)
    response_register_user_dict = response_register_user[0]
    if not response_register_user[1]:
        print("register user failed %s" % response_register_user_dict)
        return
    print("register user success")
    response_register_package_content = register_package_content(name=random_package_content_name, content_value=random_content_value)
    response_register_package_content_dict = response_register_package_content[0]
    if not response_register_package_content[1]:
        print("register package_content failed %s" % response_register_package_content_dict)
        return
    response_register_package = register_package(
        name=random_package_name, package_contents=[response_register_package_content_dict["package_content"]["id"]]  # type: ignore
    )
    response_register_package_dict = response_register_package[0]
    if not response_register_package[1]:
        print("register package failed %s " % response_register_package)
        return
    print("register package success")
    print(response_register_package_dict)
    response_register_user_package = register_user_package(
        user_id=response_register_user_dict["user"]["id"], package_id=response_register_package_dict["package"]["id"]  # type: ignore
    )
    if not response_register_user_package[1]:
        print(f"register user_package failed: { response_register_user_package}")
        return
    print("register user_package success")
    response_login_user = login_user(name=random_user_name, ready_password=make_password_ready(random_user_name))
    if not response_login_user[1]:
        print(f"login user failed: {response_login_user}")
        return
    print("login user success")


@took_time_decorator_ns
def register_user(name: str = "ext_test_user") -> tuple[dict[str, Any], bool]:
    user_data = sample_user_data.copy()
    user_data["name"] = name
    user_data["password_hash"] = make_password_ready(name)
    request_json = {
        "model_type": "user",
        "model": user_data,
    }
    print(f"registerinng user auth: {tuple(sample_admin_data.values())}, url: {EndPoints.ARegister}, json: {request_json}")

    response = req_session.post(EndPoints.ARegister, json=request_json, auth=tuple(sample_admin_data.values()))
    return response.json(), response.ok


@took_time_decorator_ns
def register_package(
    package_contents: list[int] | None = None, name: str = "ext_test_package", detail: str = "ext_test_package_detail", days: int = 12
) -> tuple[dict[str, Any], bool]:
    package_data = sample_package_data.copy()
    package_data["name"] = name
    package_data["detail"] = detail
    package_data["days"] = days
    if package_contents is not None:
        package_data["package_contents"] = package_contents
    request_json = {
        "model_type": "package",
        "model": package_data,
    }
    print(f"registerinng package auth: {tuple(sample_admin_data.values())}, url: {EndPoints.ARegister}, json: {request_json}")
    response = req_session.post(EndPoints.ARegister, json=request_json, auth=tuple(sample_admin_data.values()))
    return response.json(), response.ok


@took_time_decorator_ns
def register_package_content(
    name: str = "ext_test_package_content", content_value: pContentEnum = "moe_gatherer"
) -> tuple[dict[str, Any], bool]:
    package_content_data = sample_package_content_data.copy()
    package_content_data["name"] = name
    package_content_data["content_value"] = content_value
    request_json = {
        "model_type": "package_content",
        "model": package_content_data,
    }
    print(f"registerinng package_content auth: {tuple(sample_admin_data.values())}, url: {EndPoints.ARegister}, json: {request_json}")
    response = req_session.post(EndPoints.ARegister, json=request_json, auth=tuple(sample_admin_data.values()))
    return response.json(), response.ok


@took_time_decorator_ns
def register_user_package(user_id: int = 1, package_id: int = 1) -> tuple[dict[str, Any], bool]:
    u_package_data = {
        "start_date": int(datetime.datetime.utcnow().timestamp()),  # IMPORTANT: this is in UTC and is int not float
        "user": user_id,
        "base_package": package_id,
    }
    request_json = {
        "model_type": "u_package",
        "model": u_package_data,
    }
    print(f"registerinng user_package auth: {tuple(sample_admin_data.values())}, url: {EndPoints.ARegister}, json: {request_json}")
    response = req_session.post(EndPoints.ARegister, json=request_json, auth=tuple(sample_admin_data.values()))

    return response.json(), response.ok


def login_user(name: str = "ext_test_user", ready_password: str = make_password_ready("ext_test_user")):
    response = req_session.post(EndPoints.ULogin, auth=(name, ready_password))

    return response.json(), response.ok


if __name__ == "__main__":
    # main()
    login_user(
        name="ext_test_user_1693337791657298046",
        ready_password=make_password_ready("ext_test_user_1693337791657298046"),
    )
