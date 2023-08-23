from hashlib import sha256

from requests import get, post

port = 2402
baseURL = f"http://0.0.0.0:{port}"

admin_auth = ("mal1kc", sha256("admin".encode()).hexdigest())


def user_olustur():
    json_data = {
        "name": "user1",
        "password_hash": sha256("user1".encode()).hexdigest(),
    }
    print(f"Kullanıcı oluşturuluyor: {json_data}")
    print(f"auth : {admin_auth}")
    r = post(baseURL + "/k_kayit", json=json_data, auth=admin_auth)
    print(r.text)
    if r.status_code == 200:
        print("Kullanıcı oluşturuldu, status code: 200")
    else:
        print("Kullanıcı oluşturulamadı , status code: ", r.status_code)


def k_kayit_get():
    r = get(baseURL + "/k_kayit", auth=admin_auth)
    print(r.text)


def p_kayit_get():
    r = get(baseURL + "/p_kayit", auth=admin_auth)
    print(r.text)


if __name__ == "__main__":
    k_kayit_get()
