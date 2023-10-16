import hashlib

encoding = "utf-8"

# TODO:HARDCODED > find a secure way for this problem
encrption_password = "owko2c0m2130x*o123k".encode(encoding)


def generate_password_salt(password: str) -> str:
    return hashlib.sha256(password.encode(encoding)).hexdigest()


def simple_dencrypt(data: bytes | str, password: str | bytes = encrption_password) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    elif not isinstance(password, bytes):
        raise TypeError("password must be str or bytes")
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, bytes):
        raise TypeError("data must be str or bytes")

    sifrelenmis = bytearray()
    for i, b in enumerate(data):
        sifrelenmis.append(b ^ password[i % len(password)])
    return bytes(sifrelenmis)


def make_password_hash(password: str) -> str:
    return hashlib.sha256(
        (password + generate_password_salt(password)).encode(encoding)
    ).hexdigest()


def make_password_ready(password: str) -> str:
    return simple_dencrypt(
        make_password_hash(password).encode(encoding), encrption_password
    ).hex()
