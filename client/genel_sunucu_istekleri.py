from hashlib import sha256

from requests import get, post
from encryption import simple_dencrypt
from datetime import datetime, timedelta
from pprint import pprint as pp

port = 8080


BASE_URL = f"http://127.0.0.1:{port}"
# production da https olursaa daha güzel olur
URL_PREFIX = f"{BASE_URL}/api/v1"


URL_ADMIN_PREFIX = "/admin"
URL_USER_PREFIX = "/user"

URLS = {
    "ULogin": URL_PREFIX + URL_USER_PREFIX + "/login",
    "ALogin": URL_PREFIX + URL_ADMIN_PREFIX + "/login",  # TODO: not implemented
    "URegister": URL_PREFIX
    + URL_ADMIN_PREFIX
    + "/register",  # currently only admin can register new users
    "APRegister": URL_PREFIX
    + URL_ADMIN_PREFIX
    + "/p_register",  # register package and package contents
    "UPRegister": URL_PREFIX
    + URL_USER_PREFIX
    + "/p_register",  # register u_package or update u_package
    # "UInfo" : URL_PREFIX_USER + "/info",
    "UPInfo": URL_PREFIX + URL_USER_PREFIX + "/p_info",
}


def sifreyi_hazirla(sifre: str):
    """
    sifreyi önce sha256 ile hashle sonra simple_dencrypt ile şifrele
    """
    return simple_dencrypt(sha256(sifre.encode()).hexdigest().encode()).decode()


admin_auth = (
    "mal1kc",
    simple_dencrypt(sha256("deov04ın-!ıj0dı12klsa".encode()).hexdigest().encode()).decode(),
)


def user_olustur():
    json_data = {
        "name": "user1",
        "password_hash": sifreyi_hazirla("user1"),
    }
    print(f"Kullanıcı oluşturuluyor: {json_data}")
    print(f"auth : {admin_auth}")
    r = post(URLS["URegister"], json=json_data, auth=admin_auth)
    print(r.text)
    if r.status_code == 200:
        print("Kullanıcı oluşturuldu, status code: 200")
    else:
        print("Kullanıcı oluşturulamadı , status code: ", r.status_code)


def user_login():
    auth_data = ("user1", sifreyi_hazirla("user1"))
    r = post(URLS["ULogin"], auth=auth_data)
    print(r.text)
    if r.status_code == 200:
        print("Kullanıcı girişi başarılı, status code: 200")
    else:
        print("Kullanıcı girişi başarısız, status code: ", r.status_code)


def add_upackage():
    u_package_data = {
        "m_type": "user_package",
        "model": {
            "base_package": 1,
            "start_data": int((datetime.utcnow() + timedelta(seconds=2)).timestamp()),
            "user": 1,
        },
    }
    r = post(URLS["UPRegister"], json=u_package_data, auth=admin_auth)
    print(r.text)
    if r.status_code == 200:
        print("user_package başarıyla eklendi", 200)
    else:
        print("user_package_oluşturma başarızı,status code: ", r.status_code)


def k_kayit_get():
    r = get(URLS["URegister"], auth=admin_auth)
    pp(r.text)


def p_kayit_get():
    r = get(URLS["UPRegister"], auth=admin_auth)
    pp(r.text)


if __name__ == "__main__":
    user_olustur()
    add_upackage()
    user_login()
    print("---")
    k_kayit_get()
    print("---")
    p_kayit_get()
