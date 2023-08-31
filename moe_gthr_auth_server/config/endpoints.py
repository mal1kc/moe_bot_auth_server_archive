from dataclasses import dataclass
import functools

URL_PREFIX = "/api/v1"
URL_PREFIX_ADMIN = URL_PREFIX + "/admin"
URL_PREFIX_USER = URL_PREFIX + "/user"


@dataclass
class _URLS:
    __slots__ = ["ULogin", "UInfo", "ALogin", "ARegister", "AInfo", "AUpdate", "ADelete"]
    ULogin: str
    UInfo: str
    ALogin: str
    ARegister: str
    AInfo: str
    AUpdate: str
    ADelete: str


@functools.lru_cache(maxsize=1, typed=True)
def _init_urls(testing=False) -> _URLS:
    if testing:
        return _URLS(
            ULogin=URL_PREFIX_USER + "/login",
            UInfo=URL_PREFIX_USER + "/info",
            ALogin=URL_PREFIX_ADMIN + "/login",
            ARegister=URL_PREFIX_ADMIN + "/register/{m_type}",
            AInfo=URL_PREFIX_ADMIN + "/info/{m_type}}/{m_id}",
            AUpdate=URL_PREFIX_ADMIN + "/update/{m_type}/{m_id}",
            ADelete=URL_PREFIX_ADMIN + "/delete/{m_type}/{m_id}",
        )
    return _URLS(
        ULogin=URL_PREFIX_USER + "/login",
        # get all user info / current session info, user_packages, user_packages_contents, \
        #    active_sessions from auth user
        UInfo=URL_PREFIX_USER + "/info",
        ALogin=URL_PREFIX_ADMIN + "/login",  # redirect to /admin/info for all db data
        ARegister=URL_PREFIX_ADMIN + "/register/<int:m_type>",
        # currently only admin can register new users
        AInfo=URL_PREFIX_ADMIN + "/info/<int:m_type>/<int:m_id>",
        AUpdate=URL_PREFIX_ADMIN + "/update/<int:m_type>/<int:m_id>",
        ADelete=URL_PREFIX_ADMIN + "/delete/<int:m_type>/<int:m_id>",
    )


URLS: _URLS = _init_urls()
