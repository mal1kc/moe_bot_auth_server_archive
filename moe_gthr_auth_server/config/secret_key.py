import os
from .. import paths


def read_enc_key() -> bytes:
    """Read the encryption key from a file."""
    return "owko2c0m2130x*o123k".encode("utf-8")  # TODO:HARDCODED


def generate_secret_key() -> bytes:
    """Generate a secret key for Flask sessions."""
    return os.urandom(24)


def write(key) -> None:
    """Write the secret key to a file."""
    paths.if_not_exists_make_file(paths.SECRET_KEY_PATH)
    with open(paths.SECRET_KEY_PATH, "wb") as file:
        file.write(key)


def read() -> bytes:
    """Read the secret key from a file."""

    if not os.path.exists(paths.SECRET_KEY_PATH):
        return generate_and_write()
    with open(paths.SECRET_KEY_PATH, "rb") as file:
        return file.read()


def generate_and_write() -> bytes:
    """
    Generate and write the secret key to a file.
    return: the secret key
    """
    key = generate_secret_key()
    write(key)
    return key


if __name__ == "__main__":
    key = generate_secret_key()
    write(key)
    print("Secret key generated and written to %s." % paths.SECRET_KEY_PATH)
    print("Keep this key secret!")
    print("If you lose this key, you will have to log in again.")
    print(
        "If you want to change this key, delete %s and restart the server."
        % paths.SECRET_KEY_PATH
    )
