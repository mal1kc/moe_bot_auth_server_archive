"""#helper functions for tests"""
import logging
import random

import moe_bot_auth_server.config.endpoints as app_config_endpoints
from moe_bot_auth_server.database_ops import timezone_timestamp  # noqa
from moe_bot_auth_server.database_ops import Admin, Package, PackageContent, User
from moe_bot_auth_server.enums import mType, pContentEnum  # noqa

LOGGER = logging.getLogger("testing_helpers")

URLS = app_config_endpoints._init_urls(testing=True)


def show_db_data(app_contx):
    with app_contx:
        print("Admins:")
        for admin in Admin.query.all():
            print(admin)
        print("Users:")
        for user in User.query.all():
            print(user)
        print("Packages:")
        for package in Package.query.all():
            print(package)
        print("PackageContents:")
        for package_content in PackageContent.query.all():
            print(package_content)


def generate_random_sized_random_package_content_list(max_size: int = 4):
    size_list = random.randint(a=1, b=max_size)
    result = []
    available_pContent = list(pContentEnum)
    while len(result) < size_list:
        p_content = random.choice(available_pContent)
        if p_content not in result:
            result.append(p_content)
    LOGGER.debug("generate_random_sized_random_content_list: -> result:{}".format(result))
    return result
