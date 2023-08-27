password = "owko2c0m2130x*o123k".encode("utf-8")  # TODO:HARDCODED


def simple_dencrypt(data: bytes | str, password: str | bytes = password) -> bytes:
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
