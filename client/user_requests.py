import requests  # noqa
from endpoints import Endpoints  # noqa
from data import (
    sample_user_data,
)  # noqa


def get_user_info():
    response = requests.get(
        Endpoints.UInfo, auth=(sample_user_data["name"], sample_user_data["password_hash"])
    )
    return response.json()


def main():
    ...


if __name__ == "__main__":
    main()
