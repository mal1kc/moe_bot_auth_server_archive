PORT = 5000

BASE_URL = f"http://127.0.0.1:{PORT}"
URL_PREFIX = f"{BASE_URL}/api/v1"


URL_ADMIN_PREFIX = "/admin"
URL_USER_PREFIX = "/user"

URLS = {
    "ULogin": URL_PREFIX + URL_USER_PREFIX + "/login",
    "UInfo": URL_PREFIX + URL_USER_PREFIX + "/info",
    # /user/info -> get all user info / curren session info, user_packages, user_packages_contents, active_sessions
    "ALogin": URL_PREFIX + URL_ADMIN_PREFIX + "/login",
    "ARegister": URL_PREFIX + URL_ADMIN_PREFIX + "/register",  # currently only admin can register new users
    "AInfo": URL_PREFIX + URL_ADMIN_PREFIX + "/info",
    # /admin/info/m_type/{id} |  /admin/update/m_type/{id}
    #   -> m_type = 0 -> user, m_type = 1 -> package, m_type = 2 -> package_content, m_type = 3 -> u_package
    #       -> m_type = 4 -> u_session
    "AUpdate": URL_PREFIX + URL_ADMIN_PREFIX + "/update",
}


class _EndPoints(object):
    __slots__ = (
        "ULogin",
        "UInfo",
        "ALogin",
        "ARegister",
        "AInfo",
    )

    def __init__(self, ULogin, UInfo, ALogin, ARegister, AInfo):
        self.ULogin = ULogin
        self.UInfo = UInfo
        self.ALogin = ALogin
        self.ARegister = ARegister
        self.AInfo = AInfo


def _make_endpoints():
    return _EndPoints(
        ULogin=URLS["ULogin"],
        UInfo=URLS["UInfo"],
        ALogin=URLS["ALogin"],
        ARegister=URLS["ARegister"],
        AInfo=URLS["AInfo"],
    )


EndPoints = _make_endpoints()
