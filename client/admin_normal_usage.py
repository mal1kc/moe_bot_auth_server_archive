from pprint import pprint

from admin_requests import get_info
from data import mTypes
from utils import admin_header_kwargs
from moe_bot_auth_server.database_ops import timezone_timestamp


def main():
    # get user info with id 2
    get_info_result, is_ok = get_info(
        m_type=mTypes.user, m_id=2, admin_header_kwargs=admin_header_kwargs
    )
    pprint(get_info_result)
    print("-" * 50)
    print("Sessions:")
    for session in get_info_result["user"]["sessions"]:
        print(
            "Session id: {}, start_date: {}, end_date: {}".format(
                session["id"],
                timezone_timestamp(session["start_date"]),
                timezone_timestamp(session["end_date"]),
            )
        )


if __name__ == "__main__":
    main()
