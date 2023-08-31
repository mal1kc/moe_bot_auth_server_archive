#!/usr/bin/env python3
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import random
import string


# class AESCipher(object):
#     def __init__(self, key):
#         self.block_size = AES.block_size
#         self.key = hashlib.sha256(key).digest()

#     def encrypt(self, plain_text):
#         plain_text = self.__pad(plain_text)
#         iv = Random.new().read(self.block_size)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         encrypted_text = cipher.encrypt(plain_text.encode())
#         return b64encode(iv + encrypted_text).decode("utf-8")

#     def decrypt(self, encrypted_text):
#         encrypted_text = b64decode(encrypted_text)
#         iv = encrypted_text[: self.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         plain_text = cipher.decrypt(encrypted_text[self.block_size :]).decode("utf-8")
#         return self.__unpad(plain_text)

#     def __pad(self, plain_text):
#         number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
#         ascii_string = chr(number_of_bytes_to_pad)
#         padding_str = number_of_bytes_to_pad * ascii_string
#         padded_plain_text = plain_text + padding_str
#         return padded_plain_text

#     @staticmethod
#     def __unpad(plain_text):
#         last_character = plain_text[len(plain_text) - 1 :]
#         return plain_text[: -ord(last_character)]

bytes64 = bytes  # type alias for bytes with length 64


class AESCipher(object):
    def __init__(self, key: bytes = "someDummyKey"):
        self.block_size = AES.block_size
        if key is None:
            key = "someDummyKey"
        if isinstance(key, str):
            key = key.encode()
        elif not isinstance(key, bytes):
            raise TypeError("key must be str or bytes")
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text: str) -> str:
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text)
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text: bytes64) -> str:
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size :])
        plain_text = plain_text.decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text: str) -> str:
        pt = plain_text.encode()
        padded_plain_text = pt + b"\0" * (AES.block_size - len(pt) % AES.block_size)
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text) -> str:
        return plain_text.rstrip(b"\0".decode())


def random_string(length: int) -> str:
    """Generate a random string of length."""
    char_list = string.ascii_letters + string.digits + string.punctuation + "üğşçöı"
    return "".join(random.choice(char_list) for _ in range(length))


def random_key(size_in_bits: int = 256) -> bytes:
    """Generate a random key of size_in_bits."""
    return Random.get_random_bytes(size_in_bits // 8)


def test_aes(password, plain_text):
    print("Plain text: %s" % plain_text)
    aes = AESCipher(password)
    print("password: %s" % password)
    encrypted_text = aes.encrypt(plain_text)
    print("Encrypted text: %s" % encrypted_text)
    decrypted_text = aes.decrypt(encrypted_text)
    print("Decrypted text: %s" % decrypted_text)


def test_external_encrypted_text(password, encrypted_text, expected_plain_text):
    print("Encrypted text: %s" % encrypted_text)
    aes = AESCipher(password)
    print("password: %s" % password)
    decrypted_text = aes.decrypt(encrypted_text)
    print("Decrypted text: %s" % decrypted_text)
    assert decrypted_text == expected_plain_text, "AES decryption failed"


def main():
    test_aes("1234032ıjdmk123", "65345")
    test_aes("1234032ıjdmk123", "65345")
    test_aes("1234032ıjdmk123", "65345")
    test_external_encrypted_text(
        "1234032ıjdmk123", "ke0RUf3gj4o2/v/OLIHpQWXIacicAbOCfYKSDJQA5E8=", "65345"
    )
    test_external_encrypted_text(
        "1234032ıjdmk123", "QjTZZwVzZ3o1amVCZ3X3YqbunEt8azcejuIwPzq2kN8=", "65345"
    )


def test_aes_million_random_iter():
    prev_encrypted_text = None
    for i in range(1000000):
        password = "1234032ıjdmk123"
        aes = AESCipher(password)
        plain_text = random_string(random.randint(20, 256))
        encrypted_text = aes.encrypt(plain_text)
        decrypted_text = aes.decrypt(encrypted_text)
        assert plain_text == decrypted_text
        if i % 10000 == 0:
            if prev_encrypted_text is not None:
                if prev_encrypted_text == encrypted_text:
                    print("Test %d failed" % i)
                    break
            else:
                prev_encrypted_text = encrypted_text
            print("Test %d passed" % i)


if __name__ == "__main__":
    main()
    # test_aes_million_random_iter()
