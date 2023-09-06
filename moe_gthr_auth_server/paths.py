import os


def if_not_exists_make_dir(path: str) -> str:
    """Make a directory if it doesn't exist."""
    if not os.path.exists(path):
        print("dir not exists creating ->", path)
        os.makedirs(path)
    return path


def if_not_exists_make_file(path: str) -> str:
    """Make a file if it doesn't exist."""
    dir = os.path.dirname(path)
    if not os.path.exists(dir):
        print("dir not exists creating ->", dir)
        os.makedirs(dir)
        return if_not_exists_make_file(path)
    if not os.path.exists(path):
        print("path not exists creating ->", path)
        open(path, "w").close()
    return path


DATA_DIR = if_not_exists_make_dir(os.path.join(os.path.dirname(__file__), "../data"))
CONFIG_DIR = if_not_exists_make_dir(os.path.join(os.path.dirname(__file__), "../config"))
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, "config.toml")
DB_PATH = os.path.join(DATA_DIR, "moe_gthr_auth_srvr.db")
SECRET_KEY_PATH = os.path.join(CONFIG_DIR, "secret_key")
LOG_PATH = os.path.join(DATA_DIR, "moe_gthr_auth_srvr.log")
