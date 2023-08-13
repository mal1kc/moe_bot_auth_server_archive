from hashlib import sha256

from requests import post


def kullanici_olustur():
    data = {
        "k_adi": "user1",
        "k_sifre": sha256("user1".encode()).hexdigest(),
    }
    print(f"Kullanıcı oluşturuluyor: {data}")
    auth = ("mal1kc", sha256("admin".encode()).hexdigest())
    print(f"auth : {auth}")
    r = post("http://localhost:5000/kayit", data=data, auth=auth)
    # r = post("http://localhost:5000/kayit", data=data)
    print(r.text)
    if r.status_code == 200:
        print("Kullanıcı oluşturuldu, status code: 200")
    else:
        print("Kullanıcı oluşturulamadı , status code: ", r.status_code)


if __name__ == "__main__":
    kullanici_olustur()
