from hashlib import sha256

from requests import get, post

port = 2402
admin_auth = ("mal1kc", sha256("admin".encode()).hexdigest())

BASE_URL = f"http://0.0.0.0:{port}"
URL_PREFIX = "/api/v1"


URL_ADMIN_PREFIX = "/admin"
URL_USER_PREFIX = "/user"

URLS = {
    "ULogin": URL_PREFIX + URL_USER_PREFIX + "/login",
    "ALogin": URL_PREFIX + URL_ADMIN_PREFIX + "/login",  # TODO: not implemented
    "URegister": URL_PREFIX + URL_ADMIN_PREFIX + "/register",  # currently only admin can register new users
    "APRegister": URL_PREFIX + URL_ADMIN_PREFIX + "/p_register",  # register package and package contents
    "UPRegister": URL_PREFIX + URL_USER_PREFIX + "/p_register",  # register u_package or update u_package
    # "UInfo" : URL_PREFIX_USER + "/info",
    "UPInfo": URL_PREFIX + URL_USER_PREFIX + "/p_info",
}


def user_olustur():
    json_data = {
        "name": "user1",
        "password_hash": sha256("user1".encode()).hexdigest(),
    }
    print(f"Kullanıcı oluşturuluyor: {json_data}")
    print(f"auth : {admin_auth}")
    r = post(URLS["URegister"], json=json_data, auth=admin_auth)
    print(r.text)
    if r.status_code == 200:
        print("Kullanıcı oluşturuldu, status code: 200")
    else:
        print("Kullanıcı oluşturulamadı , status code: ", r.status_code)


def k_kayit_get():
    r = get(URLS["URegister"], auth=admin_auth)
    print(r.text)


def p_kayit_get():
    r = get(URLS["UPRegister"], auth=admin_auth)
    print(r.text)


if __name__ == "__main__":
    k_kayit_get()
