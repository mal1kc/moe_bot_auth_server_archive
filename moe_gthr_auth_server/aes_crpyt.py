from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
import hashlib

from .config.secret_key import read_aes_key


bytes64 = bytes  # type alias for bytes with length 64

# IMPORTANT: CURRENTLY, THIS IS ONLY USED FOR PASSWORDS


class AESCipher(object):
    def __init__(self, key: bytes = read_aes_key()):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text: str) -> str:
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text: bytes64) -> str:
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size :]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text) -> str:
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text) -> str:
        last_character = plain_text[len(plain_text) - 1 :]
        return plain_text[: -ord(last_character)]
