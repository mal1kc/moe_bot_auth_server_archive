import requests  # noqa

from data import sample_user_data
from encryption import make_password_ready
from endpoints import EndPoints
from utils import requests_session


def login_user(
    name: str = "ext_test_user",
    ready_password: str = make_password_ready("ext_test_user"),
    request_session=requests_session,
):
    response = request_session.post(EndPoints.ULogin, auth=(name, ready_password))

    return response.json(), response.ok


def get_user_info():
    response = requests.get(
        EndPoints.UInfo, auth=(sample_user_data["name"], sample_user_data["password_hash"])
    )
    return response.json()


def main():
    ...


if __name__ == "__main__":
    main()
