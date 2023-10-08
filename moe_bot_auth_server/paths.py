import os


def if_not_exists_make_dir(path: str, relative: bool = True) -> str:
    """Make a directory if it doesn't exist."""
    if relative:
        # file structure:

        # __file__ as this_file -> moe_bot_auth_server/paths.py
        # os.path.dirname(__file__) -> moe_bot_auth_server
        # os.path.dirname(os.path.dirname(__file__)) -> .

        # -| moe_bot_auth_server
        #   -| paths.py
        #   -| config
        #     -| flask.py
        # - config
        #  -| config.toml
        # - static
        # - templates

        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), path)
    if not os.path.exists(path):
        print("dir not exists creating ->", path)
        os.makedirs(path, exist_ok=True)
    elif not os.path.isdir(path):
        raise ValueError("path is not a directory -> {}".format(path))
    return path


def if_not_exists_make_file(path: str, relative: bool = True) -> str:
    """Make a file if it doesn't exist."""
    if relative:
        path = os.path.join(os.path.dirname(__file__), path)
    if_not_exists_make_dir(os.path.dirname(path), relative=False)
    if not os.path.exists(path):
        print("path not exists creating ->", path)
        open(path, "w").close()
    return path


CONFIG_FILE_PATH = if_not_exists_make_file("../config/config.toml", relative=True)
