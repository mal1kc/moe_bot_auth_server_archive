import datetime
import enum

from encryption import make_password_ready


class pContentEnum(enum.StrEnum):
    moe_gatherer = enum.auto()  # -> "moe_gatherer"
    moe_advantures = enum.auto()
    moe_camp = enum.auto()
    moe_arena = enum.auto()
    moe_raid = enum.auto()
    extra_session = enum.auto()
    discord = enum.auto()


class mTypes(enum.IntEnum):
    "enum for model types"
    "values are coming from serverside values"
    user = 0
    package_content = 1
    package = 2
    u_package = 3
    u_session = 4


sample_admin_data = {
    "name": "ncmdn",
    "password_hash": make_password_ready("159753aA"),
}

sample_user_data = {
    "name": "ext_test_user",
    "password_hash": make_password_ready("ext_test_user_password"),
}

sample_user_data2 = {
    "name": "ext_test_user2",
    "password_hash": make_password_ready("ext_test_user_password2"),
}

sample_package_data = {
    "name": "ext_test_package",
    "days": 12,
    "detail": "ext_test_package_detail",
    "package_contents": [],
}

# package_contents is list of package_content id

sample_package_data2 = {
    "name": "ext_test_package2",
    "days": 12,
    "detail": "ext_test_package_detail2",
    "package_contents": [0, 5],
}

sample_package_content_data = {
    "name": "ext_test_package_content",
    "content_value": pContentEnum.moe_gatherer,
}

# base_package = 0, user = 0 is id of user and package
sample_u_package_data = {
    "start_date": datetime.datetime.now(),
    "base_package": 0,
    "user": 0,
}
