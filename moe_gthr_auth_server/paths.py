import os


def if_not_exists_make_dir(path):
    """Make a directory if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)
    return path


def if_not_exists_make_file(path):
    """Make a file if it doesn't exist."""
    dir = os.path.dirname(path)
    if not os.path.exists(dir):
        os.makedirs(dir)
        open(path, "w").close()
        return path
    if not os.path.exists(path):
        open(path, "w").close()
    return path


DATA_DIR = if_not_exists_make_dir(os.path.join(os.path.dirname(__file__), "data"))
CONFIG_DIR = if_not_exists_make_dir(os.path.join(os.path.dirname(__file__), "config"))
DB_PATH = os.path.join(DATA_DIR, "moe_gthr_auth_srvr.db")
SECRET_KEY_PATH = os.path.join(CONFIG_DIR, "secret_key")
LOG_PATH = os.path.join(DATA_DIR, "moe_gthr_auth_srvr.log")
