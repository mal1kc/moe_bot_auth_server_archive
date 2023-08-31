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
def _init_urls() -> _URLS:
    return _URLS(
        ULogin=URL_PREFIX_USER + "/login",
        UInfo=URL_PREFIX_USER + "/info",
        ALogin=URL_PREFIX_ADMIN + "/login",  # TODO: not implemented
        ARegister=URL_PREFIX_ADMIN + "/register",  # currently only admin can register new users
        AInfo=URL_PREFIX_ADMIN + "/info",
        AUpdate=URL_PREFIX_ADMIN + "/update",
        ADelete=URL_PREFIX_ADMIN + "/delete",
    )


URLS: _URLS = _init_urls()
