from .. import paths

LOGGING_LEVEL = "INFO"

SQLALCHEMY_DATABASE_URI = "sqlite:///" + paths.DB_PATH
SQLALCHEMY_TRACK_MODIFICATIONS = False

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
