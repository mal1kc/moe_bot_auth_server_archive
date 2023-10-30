import functools
import os
import tomllib
import logging.config

from moe_bot_auth_server.paths import if_not_exists_make_dir, if_not_exists_make_file


ENV_PREFIX = "MOE_BOT_SERV_"


class Config:
    __slots__ = (
        "DEBUG",
        "LOG_LEVEL",
        "LOG_FILE_MAX_SIZE",
        "LOG_MAX_FILES",
        "LOG_FILE_FOLDER",
        "SQLALCHEMY_DATABASE_URI",
        "SQLALCHEMY_TRACK_MODIFICATIONS",
        "USER_SESSION_TIMEOUT",
        "USER_OLDEST_SESSION_TIMEOUT",
        "USER_IP_SESSION_LIMIT",
        "SECRET_KEY",
        "DATA_FOLDER",
        "STATIC_FOLDER",
        "TEMPLATE_FOLDER",
        "ADMINS",
    )
    OVERRIDE_FROM_ENV = True

    def __init__(self, **kwargs):
        """
        if want default values, give {} as kwargs
        if want to override default values, give kwargs
        override_from_env : if True, override values with env values
        """
        if Config.OVERRIDE_FROM_ENV:
            env_config = Config.from_env(_internal=True)
            kwargs.update(env_config)

        for key in kwargs:
            if key not in self.__slots__:
                raise ValueError("invalid config key : {}".format(key))
            elif key == "ADMINS":
                for admin in kwargs[key]:
                    if "username" not in admin or "password_hash" not in admin:
                        raise ValueError("invalid config key : {}".format(key))
                    elif len(admin["username"]) < 3 or len(admin["username"]) > 20:
                        raise ValueError("invalid config key : {}".format(key))
                    elif len(admin["password_hash"]) != 64:
                        raise ValueError("invalid config key : {}".format(key))
            elif key == "SQLALCHEMY_DATABASE_URI" and kwargs[key].endswith("sqlite3"):
                parsed_to_fname = kwargs[key].split("///")[1]
                if_not_exists_make_dir(os.path.dirname(parsed_to_fname))
                setattr(self, key, kwargs[key])
            elif key.endswith("LOCATION"):
                kwargs[key] = if_not_exists_make_file(kwargs[key])
            elif key.endswith("_FOLDER"):
                kwargs[key] = if_not_exists_make_dir(kwargs[key])

        for key, value in kwargs.items():
            if key in self.__slots__:
                setattr(self, key, value)

        # check empty values
        # if empty, set default
        for key in self.__slots__:
            if getattr(self, key, None) is None:
                env_config = {}
                default_config = Config.from_defaults()
                if key in env_config:
                    setattr(self, key, env_config[key])
                else:
                    setattr(self, key, default_config[key])
        self.configure_logging()

    def __repr__(self) -> str:
        return "<Config {}>".format([(key, getattr(self, key)) for key in self.__slots__])

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def from_defaults():
        return {
            "DEBUG": False,
            "LOG_LEVEL": "INFO",
            "LOG_FILE_MAX_SIZE": 1024 * 1024 * 10,  # 10 MB
            "LOG_MAX_FILES": 3,
            "LOG_FILE_FOLDER": "../logs",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///{data_folder}/db.sqlite3".format(
                data_folder=if_not_exists_make_dir("data", relative=True)
            ),
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "USER_SESSION_TIMEOUT": 30,  # in seconds
            "USER_OLDEST_SESSION_TIMEOUT": 24,  # in hours
            "USER_IP_SESSION_LIMIT": 150,
            "SECRET_KEY": "no-so-secret-key1235120m98c2123*9zxı",
            "DATA_FOLDER": if_not_exists_make_dir("data", relative=True),
            "STATIC_FOLDER": if_not_exists_make_dir("static", relative=True),
            "TEMPLATE_FOLDER": if_not_exists_make_dir("templates", relative=True),
            "ADMINS": [
                {
                    "username": "mstafa",
                    "password_hash": "***REMOVED***",  # noqa : E501
                },
                {
                    "username": "ncmdn",
                    "password_hash": "***REMOVED***",  # noqa : E501
                },
            ],
        }

    @staticmethod
    def from_toml(path):
        with open(path, "rb") as f:
            config = tomllib.load(f)
        return Config(**config)

    @staticmethod
    def from_env(_internal=False):
        config_dict = {}
        for key, value in os.environ.items():
            if key.startswith(ENV_PREFIX):
                config_dict[key[len(ENV_PREFIX) :]] = value
        if _internal:
            return config_dict
        return Config(**config_dict)

    @staticmethod
    def from_env_file(path):
        config_dict = {}
        with open(path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                key, value = line.split("=")
                if key.startswith(ENV_PREFIX):
                    config_dict[key[len(ENV_PREFIX) :]] = value
        return Config(**config_dict)

    def configure_logging(self):
        if not os.path.exists(self.LOG_FILE_FOLDER):
            os.makedirs(self.LOG_FILE_FOLDER)
        logging.config.dictConfig(
            {
                "version": 1,
                "disable_existing_loggers": True,
                "formatters": {
                    "default": {
                        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "formatter": "default",
                        "filename": self.LOG_FILE_FOLDER + "/app.log",
                        "maxBytes": self.LOG_FILE_MAX_SIZE,
                        "backupCount": self.LOG_MAX_FILES,
                    },
                    "db_op_file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "formatter": "default",
                        "filename": self.LOG_FILE_FOLDER + "/db_op.log",
                        "maxBytes": self.LOG_FILE_MAX_SIZE,
                        "backupCount": self.LOG_MAX_FILES,
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "formatter": "default",
                    },
                },
                "loggers": {
                    "gunicorn": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["file", "console"],
                    },
                    "gunicorn.access": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["file", "console"],
                    },
                    "gunicorn.error": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["file", "console"],
                    },
                    "sqlalchemy_db": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["db_op_file", "console"],
                    },
                    "data_schema_validation": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["file", "console"],
                    },
                    "cli": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["console"],
                    },
                    "main_app": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["file", "console"],
                    },
                    "admin_control": {
                        "level": self.LOG_LEVEL,
                        "handlers": ["file", "console"],
                    },
                },
            }
        )

    def __iter__(self):
        for key in self.__slots__:
            yield key, getattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)
