import pytest
import datetime
import random

from flask import Flask

from moe_gthr_auth_server import register_blueprints, register_error_handlers
from moe_gthr_auth_server.database_ops import (
    Admin,
    Package,
    PackageContent,
    U_Package,
    User,
    add_admin,
    db,
    pContentEnum,
    utc_timestamp,
)
from moe_gthr_auth_server.crpytion import (
    make_password_hash,
    make_password_ready,
)

from tests.testing_helpers import LOGGER, generate_random_sized_random_package_content_list


@pytest.fixture
def app():
    app = Flask("moe_gatherer_server")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    LOGGER.debug("app: %s", app)
    register_blueprints(app)
    register_error_handlers(app)
    db.init_app(app)
    yield app


@pytest.fixture
def app_ctx(app):
    return app.app_context()


@pytest.fixture
def admin_db_data() -> dict:
    return {
        "name": "ext_test_admin",
        "password_hash": make_password_hash("ext_test_admin_password"),
    }


@pytest.fixture
def admin_data(admin_db_data) -> dict:
    return {
        "name": admin_db_data["name"],
        "password_hash": make_password_ready("ext_test_admin_password"),
    }


@pytest.fixture
def user_db_data() -> dict:
    return {
        "name": "ext_test_user",
        "password_hash": make_password_hash("ext_test_user_password"),
    }


@pytest.fixture
def user_data() -> dict:
    return {
        "name": "ext_test_user",
        "password_hash": make_password_ready("ext_test_user_password"),
    }


@pytest.fixture(autouse=True)
def init_db(app_ctx, admin_db_data):
    LOGGER.debug("init_db")
    with app_ctx:
        db.create_all()
        db_Admin = Admin(**admin_db_data)
        for pcontent in pContentEnum:
            db_PackageContent = PackageContent(
                name=pcontent,
                content_value=pcontent,
            )
            db.session.add(db_PackageContent)
        add_admin(db_Admin)
        yield
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def show_db_data(app_contx=app_ctx):
    LOGGER.debug("show_db_data")
    with app_contx:
        db_admins = Admin.query.all()
        LOGGER.debug("db_admins: %s", db_admins)
        for db_admin in db_admins:
            LOGGER.debug("db_admin: %s", db_admin)
        db_users = User.query.all()
        LOGGER.debug("db_users: %s", db_users)
        for db_user in db_users:
            LOGGER.debug("db_user: %s", db_user)
        db_packages = Package.query.all()
        LOGGER.debug("db_packages: %s", db_packages)
        for db_package in db_packages:
            LOGGER.debug("db_package: %s", db_package)
            LOGGER.debug("db_package.package_contents: %s", db_package.package_contents)
        db_package_contents = PackageContent.query.all()
        LOGGER.debug("db_package_contents: %s", db_package_contents)
        for db_package_content in db_package_contents:
            LOGGER.debug("db_package_content: %s", db_package_content)
        db_user_packages = U_Package.query.all()
        LOGGER.debug("db_user_packages: %s", db_user_packages)
        for db_user_package in db_user_packages:
            LOGGER.debug("db_user_package: %s", db_user_package)
        LOGGER.debug("show_db_data: OK")


@pytest.fixture
def admin_data_auth(admin_data) -> tuple:
    return (admin_data["name"], admin_data["password_hash"])


@pytest.fixture
def user_data_model_json(user_data) -> dict:
    return {"model_type": "user", "user": {*user_data}}


@pytest.fixture
def package_data() -> dict:
    return {"name": "ext_test_package", "detail": "ext_test_package_detail", "days": 12}


@pytest.fixture
def package_content_data() -> dict:
    return {"name": "ext_test_package_content", "content_value": "extra_user"}


@pytest.fixture
def package_data_with_package_content(package_data, package_content_data) -> dict:
    package_data["package_contents"] = [package_content_data]
    return package_data


@pytest.fixture
def random_package_content_data() -> dict:
    random_cotent_value = random.choice([pi for pi in pContentEnum])
    return {
        "name": "ext_test_package_content" + str(random_cotent_value),
        "content_value": random_cotent_value,
    }


@pytest.fixture
def u_package_data() -> dict:
    return {
        "user": 1,
        "base_package": 1,
        "start_date": utc_timestamp(datetime.datetime.utcnow()),
    }


@pytest.fixture
def user_data_auth(user_data) -> tuple:
    return (user_data["name"], user_data["password_hash"])


@pytest.fixture
def update_sample_user_data() -> dict:
    return {
        "name": "ext_test_user_updated",
        "password_hash": make_password_ready("ext_test_user_password_updated"),
    }


@pytest.fixture
def update_sample_package_data() -> dict:
    return {
        "name": "ext_test_package_updated",
        "detail": "ext_test_package_detail_updated",
        "days": 12,
        "package_contents": [],
    }


@pytest.fixture
def update_sample_package_content_data() -> dict:
    return {
        "name": "ext_test_package_content_updated",
        "content_value": "extra_user",
    }


@pytest.fixture
def update_sample_u_package_data() -> dict:
    return {
        "user": 1,
        "base_package": 1,
        "start_date": utc_timestamp(datetime.datetime.utcnow()),
    }


@pytest.fixture
def update_sample_package_with_package_content_data() -> dict:
    return {
        "name": "ext_test_package_updated",
        "detail": "ext_test_package_detail_updated",
        "days": 12,
        "package_contents": [1, 2],
    }


@pytest.fixture
def package_data_with_random_content_datas(package_data) -> dict:
    pcontents = generate_random_sized_random_package_content_list()
    LOGGER.debug("package_data_with_random_content_list: pcontents: %s", pcontents)
    package_content_datas = [
        {"name": pcontent, "content_value": pcontent} for pcontent in pcontents
    ]
    LOGGER.debug(
        "package_data_with_random_content_list: package_content_datas: %s",
        package_content_datas,
    )
    package_data["package_contents"] = package_content_datas
    return package_data


@pytest.fixture
def app_db_add_users(app_ctx, user_db_data):
    """
    Add 50 users to the database
    with names and passwords like ext_test_user1, ext_test_user2, ... ext_test_user49
    """
    user_count_range = range(1, 50)
    LOGGER.debug("app_db_add_users")
    users_db_data = [
        {
            "name": user_db_data["name"] + str(i),
            "password_hash": make_password_hash(user_db_data["password_hash"] + str(i)),
        }
        for i in user_count_range
    ]
    with app_ctx:
        db_users = [User(**user_db_data) for user_db_data in users_db_data]
        db.session.add_all(db_users)
        db.session.commit()
        yield True
        db.session.remove()


@pytest.fixture
def user_from_db(
    app_ctx,
    user_db_data,
):
    LOGGER.debug("user_from_db")
    with app_ctx:
        db_user = User(**user_db_data)
        db.session.add(db_user)
        db.session.commit()
        db_query_user = User.query.filter_by(name=user_db_data["name"]).first()
        yield db_query_user
        db.session.remove()


@pytest.fixture
def package_from_db(
    app_ctx,
    package_data,
):
    LOGGER.debug("package_from_db")
    with app_ctx:
        db_package = Package(**package_data)
        db.session.add(db_package)
        db.session.commit()
        db_query_package = Package.query.filter_by(name=package_data["name"]).first()
        yield db_query_package
        db.session.remove()


@pytest.fixture
def random_package_content_from_db(
    app_ctx,
    random_package_content_data,
):
    LOGGER.debug("random_package_content_data")
    with app_ctx:
        db_package_content = PackageContent(**random_package_content_data)
        db.session.add(db_package_content)
        db.session.commit()
        db_query_package_content = PackageContent.query.filter_by(
            name=random_package_content_data["name"]
        ).first()
        yield db_query_package_content
        db.session.remove()


@pytest.fixture
def random_package_contents_from_db(
    app_ctx,
):
    LOGGER.debug("random_package_content_data")
    with app_ctx:
        randomized_package_content_datas = (
            generate_random_sized_random_package_content_list()
        )
        db_package_contents = [
            PackageContent(
                name=pcontent,
                content_value=pcontent,
            )
            for pcontent in randomized_package_content_datas
        ]
        for db_package_content in db_package_contents:
            db_query_package_content = PackageContent.query.filter_by(
                name=db_package_content.name
            ).first()
            if not db_query_package_content:
                db.session.add(db_package_content)
        db.session.commit()
        db_query_package_contents = PackageContent.query.all()
        yield db_query_package_contents
        db.session.remove()


@pytest.fixture
def second_user_from_db(
    app_ctx,
    user_db_data,
):
    LOGGER.debug("second_user_from_db")
    with app_ctx:
        db_user = User(
            name=user_db_data["name"] + "2",
            password_hash=make_password_hash(user_db_data["password_hash"] + "2"),
        )
        db.session.add(db_user)
        db.session.commit()
        db_query_user = User.query.filter_by(name=db_user.name).first()
        yield db_query_user
        db.session.remove()


@pytest.fixture
def u_package_from_db(
    app_ctx,
    user_from_db,
    package_from_db,
    u_package_data,
):
    LOGGER.debug("u_package_from_db")
    with app_ctx:
        u_package_data["user"] = user_from_db.id
        u_package_data["base_package"] = package_from_db.id
        db_u_package = U_Package(**u_package_data)
        db.session.add(db_u_package)
        db.session.commit()
        db_query_u_package = U_Package.query.filter_by(
            user=user_from_db.id,
            base_package=package_from_db.id,
        ).first()
        yield db_query_u_package
        db.session.remove()