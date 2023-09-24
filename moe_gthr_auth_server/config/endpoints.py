import functools
from dataclasses import dataclass

URL_PREFIX = "/api/v1"
URL_PREFIX_ADMIN = URL_PREFIX + "/admin"
URL_PREFIX_USER = URL_PREFIX + "/user"

URL_PREFIX_ADMIN_CONTROL = "/admin_control/"


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
            AInfo=URL_PREFIX_ADMIN + "/info/{m_type}/{m_id}",
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


class _AdminControlURLS:
    __slots__ = [
        "AMain",
        "ACreate",
        "AInfo",
        "AUpdate",
        "ADelete",
        "ALogin",
        "ALogout",
        "AAbout",
    ]
    AMain: str  # main admin page
    ACreate: str  # model register
    AInfo: str
    AUpdate: str
    ADelete: str
    ALogin: str  # admin login
    ALogout: str  # admin logout
    AAbout: str  # about page

    def __init__(
        self,
        AMain: str,
        ACreate: str,
        AInfo: str,
        AUpdate: str,
        ADelete: str,
        ALogin: str,
        ALogout: str,
        AAbout: str | None = None,
    ):
        self.AMain = AMain
        self.ACreate = ACreate
        self.AInfo = AInfo
        self.AUpdate = AUpdate
        self.ADelete = ADelete
        self.ALogin = ALogin
        self.ALogout = ALogout
        self.AAbout = URL_PREFIX_ADMIN_CONTROL + "/about" if AAbout is None else AAbout


def _init_admin_control_urls() -> _AdminControlURLS:
    return _AdminControlURLS(
        AMain=URL_PREFIX_ADMIN_CONTROL,
        ACreate=URL_PREFIX_ADMIN_CONTROL + "/<model_type>/create",
        AInfo=URL_PREFIX_ADMIN_CONTROL
        + "/<model_type>/<int:model_id>/info",  # only get method
        AUpdate=URL_PREFIX_ADMIN_CONTROL
        + "/<model_type>/<int:model_id>/update",  # only put method from info page
        ADelete=URL_PREFIX_ADMIN_CONTROL + "/<model_type>/<int:model_id>/delete",
        # no template , only -delete- get method from info page and main admin page
        # (delete method not possible html forms not support delete method)
        ALogin=URL_PREFIX_ADMIN_CONTROL + "/login",  # only post method
        ALogout=URL_PREFIX_ADMIN_CONTROL + "/logout",  # only post method
    )


@functools.lru_cache(maxsize=1, typed=True)
def _create_formatible_admin_control_urls() -> _AdminControlURLS:  # noqa
    return _AdminControlURLS(
        AMain=URL_PREFIX_ADMIN_CONTROL,
        ACreate=URL_PREFIX_ADMIN_CONTROL + "/{model_type}/create",
        AInfo=URL_PREFIX_ADMIN_CONTROL + "/{model_type}/{model_id}/info",  # only get method
        AUpdate=URL_PREFIX_ADMIN_CONTROL
        + "/{model_type}/{model_id}/update",  # only put method from info page
        ADelete=URL_PREFIX_ADMIN_CONTROL + "/{model_type}/{model_id}/delete",
        ALogin=URL_PREFIX_ADMIN_CONTROL + "/login",  # only post method
        ALogout=URL_PREFIX_ADMIN_CONTROL + "/logout",  # only post method
    )


ADMIN_CONTROL_URLS: _AdminControlURLS = _init_admin_control_urls()
URLS: _URLS = _init_urls()
