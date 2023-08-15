import os

from .. import paths


def generate_secret_key():
    """Generate a secret key for Flask sessions."""
    return os.urandom(24)


def write(key):
    """Write the secret key to a file."""
    with open(paths.SECRET_KEY_PATH, "w") as file:
        file.write(key)


def read():
    """Read the secret key from a file."""
    paths.if_not_exists_make_file(paths.SECRET_KEY_PATH)
    with open(paths.SECRET_KEY_PATH, "r") as file:
        return file.read()


if __name__ == "__main__":
    key = generate_secret_key()
    write(key)
    print("Secret key generated and written to %s." % paths.SECRET_KEY_PATH)
    print("Keep this key secret!")
    print("If you lose this key, you will have to log in again.")
    print("If you want to change this key, delete %s and restart the server." % paths.SECRET_KEY_PATH)
