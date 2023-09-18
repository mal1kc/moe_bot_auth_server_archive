import os
import tomllib
from logging.config import dictConfig

from .. import paths
from .secret_key import read as secret_key_read

_SECRET_KEY = secret_key_read()
_DEBUG = True
_LOG_LEVEL = "DEBUG"
_LOG_FILE_MAX_SIZE = 1024 * 1024 * 100  # 100 MB
_LOG_MAX_FILES = 10
_LOG_FILE_LOCATION = paths.LOG_PATH
_SQLALCHEMY_DATABASE_URI = "sqlite:///" + paths.DB_PATH
_SQLALCHEMY_TRACK_MODIFICATIONS = False
_USER_SESSION_TIMEOUT = 20  # in minutes
_USER_OLDEST_SESSION_TIMEOUT = 2  # in days
_USER_IP_SESSION_LIMIT = 150


class Config:
    __slots__ = [
        "DEBUG",
        "LOG_LEVEL",
        "LOG_FILE_MAX_SIZE",
        "LOG_FILE_LOCATION",
        "LOG_MAX_FILES",
        "SQLALCHEMY_DATABASE_URI",
        "SQLALCHEMY_TRACK_MODIFICATIONS",
        "USER_SESSION_TIMEOUT",
        "USER_OLDEST_SESSION_TIMEOUT",
        "USER_IP_SESSION_LIMIT",
        "SECRET_KEY",
        "USE_SQLITE",
        "SQLITE_DATABASE_LOCATION",
    ]
    DEBUG: bool
    LOG_LEVEL: str
    LOG_FILE_MAX_SIZE: int
    LOG_FILE_LOCATION: str
    LOG_MAX_FILES: int
    SQLALCHEMY_DATABASE_URI: str
    SQLALCHEMY_TRACK_MODIFICATIONS: bool
    USER_SESSION_TIMEOUT: int
    USER_OLDEST_SESSION_TIMEOUT: int
    USER_IP_SESSION_LIMIT: int
    SECRET_KEY: str
    USE_SQLITE: bool
    SQLITE_DATABASE_LOCATION: str

    def __init__(
        self,
        debug: bool = _DEBUG,
        log_level: str = _LOG_LEVEL,
        log_file_max_size: int = _LOG_FILE_MAX_SIZE,
        log_file_location: str = _LOG_FILE_LOCATION,
        log_max_files: int = _LOG_MAX_FILES,
        sql_alchemy_database_uri: str = _SQLALCHEMY_DATABASE_URI,
        sql_alchemy_track_modifications: bool = _SQLALCHEMY_TRACK_MODIFICATIONS,
        user_session_timeout: int = _USER_SESSION_TIMEOUT,
        user_oldest_session_timeout: int = _USER_OLDEST_SESSION_TIMEOUT,
        user_ip_session_limit: int = _USER_IP_SESSION_LIMIT,
        secret_key: str = _SECRET_KEY,
        use_sqlite: bool = True,
        sqlite_database_location: str = paths.DB_PATH,
    ):
        self.DEBUG = debug
        self.LOG_LEVEL = log_level
        self.LOG_FILE_MAX_SIZE = log_file_max_size
        self.LOG_FILE_LOCATION = log_file_location
        self.LOG_MAX_FILES = log_max_files
        self.SQLALCHEMY_DATABASE_URI = sql_alchemy_database_uri
        self.SQLALCHEMY_TRACK_MODIFICATIONS = sql_alchemy_track_modifications
        self.USER_SESSION_TIMEOUT = user_session_timeout
        self.USER_OLDEST_SESSION_TIMEOUT = user_oldest_session_timeout
        self.USER_IP_SESSION_LIMIT = user_ip_session_limit
        self.SECRET_KEY = secret_key
        self.USE_SQLITE = use_sqlite
        self.SQLITE_DATABASE_LOCATION = sqlite_database_location

    @staticmethod
    def config_from_defaults():
        config = Config()
        config.configure_logging(
            file_path=config.LOG_FILE_LOCATION,
            file_max_bytes=config.LOG_FILE_MAX_SIZE,
            file_max_files=config.LOG_MAX_FILES,
            logging_level=config.LOG_LEVEL,
        )
        return config

    @staticmethod
    def load_from_toml() -> object:
        config = Config()
        try:
            if not os.path.exists(paths.CONFIG_FILE_PATH):
                print("config file not found using default config")
                return Config.config_from_defaults()
            with open(paths.CONFIG_FILE_PATH, "rb") as conf_file:
                toml_confgin = tomllib.load(conf_file)
            for key, value in toml_confgin.items():
                if key in config.__slots__ and value is not None:
                    if key.isupper():
                        if key.endswith("_LOCATION") or key.endswith("_URI"):
                            if key.endswith("_LOCATION"):
                                if paths.if_not_exists_make_file(value):
                                    setattr(config, key, value)
                                    continue
                        elif key == "DEBUG":
                            setattr(config, "LOG_LEVEL", "DEBUG")
                            setattr(config, key, bool(value))
                        else:
                            setattr(config, key, value)
                    else:
                        print(f"invalid key {key} in config file, key must be uppercase")
            if hasattr(config, "USE_SQLITE"):
                if config.USE_SQLITE and hasattr(config, "SQLITE_DATABASE_LOCATION"):
                    config.SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(
                        paths.DATA_DIR, config.SQLITE_DATABASE_LOCATION
                    )
                elif config.USE_SQLITE and not hasattr(config, "SQLITE_DATABASE_LOCATION"):
                    print(
                        "USE_SQLITE is set to true but no SQLITE_DATABASE_LOCATION is set using default database"  # noqa
                    )
                    setattr(config, "SQLALCHEMY_DATABASE_URI", _SQLALCHEMY_DATABASE_URI)
        except Exception as e:
            print(f"error while loading config file ({e})")
            return Config.config_from_defaults()
        return config

    @staticmethod
    def configure_logging(
        default_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",  # noqa
        file_path=_LOG_FILE_LOCATION,
        file_max_bytes: int = _LOG_FILE_MAX_SIZE,
        file_max_files: int = _LOG_MAX_FILES,
        logging_level=_LOG_LEVEL,
    ):
        dictConfig(
            {
                "version": 1,
                "formatters": {
                    "default": {
                        "format": default_format,
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "formatter": "default",
                        "filename": file_path,
                        "maxBytes": file_max_bytes,
                        "backupCount": file_max_files,
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "formatter": "default",
                    },
                    "db_log_file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "formatter": "default",
                        "filename": file_path.replace(".log", "_db.log"),
                        "maxBytes": file_max_bytes,
                        "backupCount": file_max_files,
                    },
                },
                "root": {
                    "level": logging_level,
                    "handlers": ["file", "console"],
                },
                "loggers": {
                    "gunicorn": {
                        "level": logging_level,
                        "handlers": ["file", "console"],
                    },
                    "gunicorn.access": {
                        "level": logging_level,
                        "handlers": ["file", "console"],
                    },
                    "gunicorn.error": {
                        "level": logging_level,
                        "handlers": ["file", "console"],
                    },
                    "sqlalchemy_db": {
                        "level": logging_level,
                        "handlers": ["db_log_file", "console"],
                    },
                    "data_schema_validation": {
                        "level": logging_level,
                        "handlers": ["file", "console"],
                    },
                    "cli": {
                        "level": logging_level,
                        "handlers": ["file", "console"],
                    },
                    "main_app": {
                        "level": logging_level,
                        "handlers": ["file", "console"],
                    },
                    "admin_control": {
                        "level": logging_level,
                        "handlers": ["file", "console"],
                    },
                },
            },
        )


def load_config_from_toml() -> object:
    return Config.load_from_toml()
