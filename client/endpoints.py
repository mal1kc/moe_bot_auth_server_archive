PORT = 8080

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


class EndPoints(object):
    __slots__ = ("ULogin", "UInfo", "ALogin", "ARegister", "AInfo")

    def __init__(self):
        if EndPoints.instance is not None:
            EndPoints.instance = self
        self.ULogin = URLS["ULogin"]
        self.UInfo = URLS["UInfo"]
        self.ALogin = URLS["ALogin"]
        self.ARegister = URLS["ARegister"]
        self.AInfo = URLS["AInfo"]

    def __repr__(self):
        return f"<EndPoints {self.__slots__}>"

    @staticmethod
    def __getitem__(item):
        if EndPoints.instance is None:
            EndPoints.instance = EndPoints()
        return getattr(EndPoints.instance, item)
