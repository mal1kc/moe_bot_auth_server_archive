#!/usr/bin/env python3
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import random
import string


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size :]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1 :]
        return plain_text[: -ord(last_character)]


# Path: aes_encrpyt_decrypt.py


def random_string(length: int) -> str:
    """Generate a random string of length."""
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


def random_key(size_in_bits: int = 256) -> bytes:
    """Generate a random key of size_in_bits."""
    return Random.get_random_bytes(size_in_bits // 8)


def get_bit_length(key: bytes) -> int:
    """Get the bit length of a key."""
    return len(key) * 8


# def test_aes_(password):
#     aes = AESCipher(password)
#     plain_text = "Hello World"
#     encrypted_text = aes.encrypt(plain_text)
#     decrypted_text = aes.decrypt(encrypted_text)
#     print("Plain text: %s" % plain_text)
#     print("password: %s" % password)
#     print("Encrypted text: %s" % encrypted_text)
#     print("Decrypted text: %s" % decrypted_text)


def main():
    print("Testing AES")
    password = random_string(16).encode()
    print("password bit size: %s" % get_bit_length(password))
    aes = AESCipher(password)
    plain_text = "somefnplainpassword"
    # encrypted_text = aes.encrypt(plain_text)
    # decrypted_text = aes.decrypt(encrypted_text)
    # print("Plain text: %s" % plain_text)
    # print("password: %s" % password.decode())
    # print("Encrypted text: %s" % encrypted_text)
    # print("Decrypted text: %s" % decrypted_text)

    # encrypted_text = aes.encrypt(plain_text)
    # decrypted_text = aes.decrypt(encrypted_text)
    # print("Plain text: %s" % plain_text)
    # print("password: %s" % password.decode())
    # print("Encrypted text: %s" % encrypted_text)
    # print("Decrypted text: %s" % decrypted_text)

    for _ in range(5):
        encrypted_text = aes.encrypt(plain_text)
        print("iv: %s" % encrypted_text[:16])
        print("decrypting %s" % encrypted_text)
        decrypted_text = aes.decrypt(encrypted_text)
        print("Plain text: %s" % plain_text)
        print("decrypted text: %s" % decrypted_text)

    encrypted_text = b"p726Vl/j3bekdNHG2KegupLWJZN18s7AEUVqU5nerz4="
    password = "SAUvPRWToJglRVUa"
    aes = AESCipher(password.encode()).decrypt(encrypted_text)
    print("Decrypted text: %s" % aes)


if __name__ == "__main__":
    main()
