import hashlib

from .config.secret_key import read_enc_key

bytes64 = bytes  # type alias for bytes with length 64

# TODO: AESCipher DOESSN'T WORK ->
#   - so utf-8 encoding , decoding errors

# class AESCipher(object):
#     def __init__(self, key: bytes = "someDummyKey".encode("utf-8")):
#         self.block_size = AES.block_size
#         if key is None:
#             key = "someDummyKey".encode("utf-8")
#         if isinstance(key, str):
#             key = key.encode()
#         elif not isinstance(key, bytes):
#             raise TypeError("key must be str or bytes")
#         self.key = hashlib.sha256(key).digest()

#     def encrypt(self, plain_text: str) -> str:
#         plain_text_bytes: bytes = self.__pad(plain_text)
#         iv = Random.new().read(self.block_size)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         encrypted_text = cipher.encrypt(plain_text_bytes)
#         return b64encode(iv + encrypted_text).decode("utf-8")

#     def decrypt(self, encrypted_text: bytes64) -> str:
#         encrypted_text = b64decode(encrypted_text)
#         iv = encrypted_text[: self.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         plain_text = cipher.decrypt(encrypted_text[self.block_size :])
#         # plain_text = plain_text
#         return self.__unpad(plain_text)

#     def __pad(self, plain_text: str) -> bytes:
#         pt = plain_text.encode()
#         padded_plain_text = pt + b"\0" * (AES.block_size - len(pt) % AES.block_size)
#         return padded_plain_text

#     @staticmethod
#     def __unpad(plain_text: bytes) -> str:
#         return plain_text.rstrip(b"\0").decode()


def simple_dencrypt(data: bytes | str, password: str | bytes = read_enc_key()) -> bytes:
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


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
