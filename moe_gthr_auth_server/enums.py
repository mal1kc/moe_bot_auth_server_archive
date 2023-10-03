from __future__ import annotations

import enum
from typing import Any


class mType(enum.IntEnum):
    "model type IntEnum"
    all_models = 255  # if you want to get all models from db
    user = 0
    package_content = 1
    package = 2
    u_package = 3
    u_session = 4


class mTypeStr(enum.StrEnum):
    "model type StrEnum"
    user = "user"
    package_content = "package_content"
    package = "package"
    u_package = "u_package"
    u_session = "u_session"


class pContentEnum(enum.StrEnum):
    "package content StrEnum for package_content model"
    # TODO : maybe change in future for more flexibility
    moe_gatherer = enum.auto()  # -> "moe_gatherer"
    moe_advantures = enum.auto()
    moe_camp = enum.auto()
    moe_arena = enum.auto()
    moe_raid = enum.auto()
    extra_user = enum.auto()
    discord = enum.auto()  # TODO: discord api kullanım hakkı


class loginError(enum.Enum):
    "login error enum"
    max_online_user = enum.auto()
    user_not_found = enum.auto()
    user_not_have_package = enum.auto()
    user_package_expired = enum.auto()
    not_found_client_ip = enum.auto()


class DBOperationResult(enum.Enum):
    "db operation result enum"
    success = True
    unknown_error = enum.auto()
    model_already_exists = enum.auto()
    model_not_found = enum.auto()
    model_not_created = enum.auto()
    model_not_updated = enum.auto()
    model_not_deleted = enum.auto()
    model_name_too_short = enum.auto()
    model_name_too_long = enum.auto()
    model_passhash_too_short = enum.auto()
    model_child_not_created = enum.auto()

    def __json__(self) -> dict[str, Any]:
        "serialize enum to json(dict[str, Any]))"
        return {"db_operation_result": self.name}
