from .. import paths
from .secret_key import read as secret_key_read

LOGGING_LEVEL = "INFO"

SQLALCHEMY_DATABASE_URI = "sqlite:///" + paths.DB_PATH
SQLALCHEMY_TRACK_MODIFICATIONS = False
USER_SESSION_TIMEOUT = 20  # in minutes
USER_OLDEST_SESSION_TIMEOUT = 2  # in days
# USER_IP_SESSION_LIMIT
# # must be bigger than (USER_OLDEST_SESSION_TIMEOUT * 24 * 60 / USER_SESSION_TIMEOUT) + 1
# # otherwise, user can't login again after USER_OLDEST_SESSION_TIMEOUT
USER_IP_SESSION_LIMIT = 150
LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
    },
    "handlers": {
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": paths.LOG_PATH,
            "maxBytes": 1024 * 1024 * 100,
            "backupCount": 10,
        },
    },
    "loggers": {
        "": {
            "handlers": ["file"],
            "level": LOGGING_LEVEL,
        },
        "test": {
            "handlers": ["file"],
            "level": "DEBUG",
        },
    },
}
SECRET_KEY = secret_key_read()
