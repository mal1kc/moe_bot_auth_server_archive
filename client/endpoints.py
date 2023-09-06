PORT = 5000
URL_PREFIX_ADMIN = "/admin"
URL_PREFIX_USER = "/user"


# IMPORTANT : NOT UP-TO-DATE
class _EndPoints(object):
    __slots__ = ["ULogin", "UInfo", "ALogin", "ARegister", "AInfo", "AUpdate", "ADelete"]
    BASE_URL = f"http://127.0.0.1:{PORT}"
    URL_PREFIX = f"{BASE_URL}/api/v1"
    ULogin: str
    UInfo: str
    ALogin: str
    ARegister: str
    AInfo: str
    AUpdate: str
    ADelete: str

    def __init__(
        self,
        ULogin: str,
        UInfo: str,
        ALogin: str,
        ARegister: str,
        AInfo: str,
        AUpdate: str,
        ADelete: str,
    ):
        self.ULogin = ULogin
        self.UInfo = UInfo
        self.ALogin = ALogin
        self.ARegister = ARegister
        self.AInfo = AInfo
        self.AUpdate = AUpdate
        self.ADelete = ADelete
        for attr in self.__slots__:
            setattr(self, attr, self.URL_PREFIX + getattr(self, attr))


def _make_endpoints():
    return _EndPoints(
        ULogin=URL_PREFIX_USER + "/login",
        UInfo=URL_PREFIX_USER + "/info",
        ALogin=URL_PREFIX_ADMIN + "/login",
        ARegister=URL_PREFIX_ADMIN + "/register/{m_type}",
        AInfo=URL_PREFIX_ADMIN + "/info/{m_type}/{m_id}",
        AUpdate=URL_PREFIX_ADMIN + "/update/{m_type}/{m_id}",
        ADelete=URL_PREFIX_ADMIN + "/delete/{m_type}/{m_id}",
    )


EndPoints: _EndPoints = _make_endpoints()
