from dataclasses import dataclass
import functools

URL_PREFIX = "/api/v1"
URL_PREFIX_ADMIN = URL_PREFIX + "/admin"
URL_PREFIX_USER = URL_PREFIX + "/user"


@dataclass
class _URLS:
    __slots__ = ["ULogin", "ALogin", "URegister", "APRegister", "UPRegister", "UPInfo"]
    ULogin: str
    ALogin: str
    URegister: str
    APRegister: str
    UPRegister: str
    UPInfo: str


@functools.lru_cache(maxsize=1)
def _init_urls() -> _URLS:
    return _URLS(
        ULogin=URL_PREFIX_USER + "/login",
        ALogin=URL_PREFIX_ADMIN + "/login",  # TODO: not implemented
        URegister=URL_PREFIX_ADMIN + "/register",  # currently only admin can register new users
        APRegister=URL_PREFIX_ADMIN + "/p_register",  # register package and package contents
        UPRegister=URL_PREFIX_USER + "/p_register",  # register u_package or update u_package
        # UInfo = URL_PREFIX_USER + "/info",
        UPInfo=URL_PREFIX_USER + "/p_info",
    )


URLS: _URLS = _init_urls()

# URLS = {
#     "ULogin": URL_PREFIX_USER + "/login",
#     "ALogin": URL_PREFIX_ADMIN + "/login", # TODO: not implemented
#     "URegister": URL_PREFIX_ADMIN + "/register", # currently only admin can register new users
#     "APRegister": URL_PREFIX_ADMIN + "/p_register", # register package and package contents
#     "UPRegister": URL_PREFIX_USER + "/p_register", # register u_package or update u_package
#     # "UInfo" : URL_PREFIX_USER + "/info",
#     "UPInfo": URL_PREFIX_USER + "/p_info",
# }
