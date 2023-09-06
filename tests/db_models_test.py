import logging
import random

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from moe_gthr_auth_server.crpytion import make_password_hash
from moe_gthr_auth_server.database_ops import (
    Admin,
    Base,
    DBOperationResult,
    Package,
    PackageContent,
    User,
    add_admin,
    add_user,
    pContentEnum,
)

test_db_engine = create_engine("sqlite:///:memory:")

LOGGER = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def _init_db():
    test_db_engine.connect()
    test_db_engine.clear_compiled_cache()
    Base.metadata.drop_all(bind=test_db_engine)
    Base.metadata.create_all(bind=test_db_engine)


@pytest.fixture
def session():
    return sessionmaker(bind=test_db_engine)()


def test_check_database_empty(session):
    assert session.query(Admin).all() == []
    assert session.query(User).all() == []
    assert session.query(Package).all() == []
    assert session.query(PackageContent).all() == []
    session.close()


@pytest.fixture
def user_data():
    return {"name": "test_user", "password_hash": make_password_hash("test_user")}


@pytest.fixture
def user(user_data) -> User:
    return User(
        name=user_data["name"],
        password_hash=user_data["password_hash"],
    )


def test_user_add(user, session, user_data):
    add_user(user, session)

    assert user == session.query(User).filter_by(name=user_data["name"]).first()
    session.close()


def test_user_password_hash(user, session, user_data):
    add_user(user, session)
    assert user.password_hash == user_data["password_hash"]
    q_user = session.query(User).filter_by(name=user_data["name"]).first()
    assert q_user.password_hash == user_data["password_hash"]
    session.close()


def test_get_user_by_id(user, session, user_data):
    add_user(user, session)
    q_user = session.query(User).filter_by(name=user_data["name"]).first()
    assert q_user == session.query(User).filter_by(id=q_user.id).first()
    session.close()


@pytest.fixture
def admin_data():
    return {"name": "test_admin", "password_hash": make_password_hash("test_admin")}


@pytest.fixture
def admin(admin_data) -> Admin:
    return Admin(
        name=admin_data["name"],
        password_hash=admin_data["password_hash"],
    )


def test_admin_add(admin, session, admin_data):
    if not session.query(Admin).filter_by(name=admin_data["name"]).first():
        add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(name=admin_data["name"]).first()
    assert q_admin == admin
    session.close()


def test_admin_password_hash(session, admin, admin_data):
    if not session.query(Admin).filter_by(name=admin_data["name"]).first():
        add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(name=admin_data["name"]).first()
    assert q_admin.password_hash == admin_data["password_hash"]
    session.close()


def test_admin_already_exists(admin, session, admin_data):
    # TODO: find cause of error when running this on its own
    if not (q_admin := session.query(Admin).filter_by(name=admin_data["name"]).first()):
        LOGGER.debug("test_admin_already_exists: q_admin: %s", q_admin)
        assert DBOperationResult.success == add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(name=admin_data["name"]).first()
    LOGGER.debug("test_admin_already_exists: after first add_admin -> q_admin: %s", q_admin)
    assert DBOperationResult.model_already_exists == add_admin(admin, session)
    q_all_admins = session.query(Admin).all()
    LOGGER.debug(
        "test_admin_already_exists: after second add_admin -> q_all_admins: %s",
        q_all_admins,
    )
    assert len(q_all_admins) == 1
    q_admin = session.query(Admin).filter_by(name=admin_data["name"]).first()
    assert q_admin.name == admin.name
    session.close()


@pytest.fixture
def package():
    return Package(name="test_package", detail="test_package_aciklama", days=30)


def test_package_add(session, package):
    session.add(package)
    session.commit()
    q_package = session.query(Package).filter_by(name=package.name).first()
    assert q_package == package
    session.close()


@pytest.fixture
def package_content(package, session):
    if not session.query(Package).filter_by(name=package.name).first():
        session.add(package)
    session.commit()
    package = session.query(Package).filter_by(name=package.name).first()
    return PackageContent(
        package_id=package.id,
        name="test_package_icerik",
        content_value=random.choice([pi for pi in pContentEnum]),
    )


def test_package_content_add(session, package, package_content):
    if not session.query(Package).filter_by(name=package.name).first():
        session.add(package)
    session.add(package_content)
    session.commit()
    q_package_contentleri = (
        session.query(PackageContent).filter(PackageContent.package_id == package.id).all()
    )
    if len(q_package_contentleri) == 0:
        package = session.query(Package).filter_by(name=package.name).first()
        q_package_contentleri = (
            session.query(PackageContent)
            .filter(PackageContent.package_id == package.id)
            .all()
        )
    assert package_content in q_package_contentleri
    session.close()


def test_package_add_random_package_content(session, package):
    if not session.query(Package).filter_by(name=package.name).first():
        session.add(package)
        session.commit()
    package = session.query(Package).filter_by(name=package.name).first()
    package_content = PackageContent(
        package_id=package.id,
        name="test_package_icerik" + str(random.randint(0, 100)),
        content_value=random.choice([pi for pi in pContentEnum]).value,
    )
    session.add(package_content)
    session.commit()
    q_package_content = (
        session.query(PackageContent)
        .filter(
            PackageContent.name == package_content.name,
            PackageContent.package_id == package.id,
        )
        .first()
    )
    assert q_package_content.content_value == package_content.content_value
    assert q_package_content.name == package_content.name
    assert q_package_content.package_id == package_content.package_id
    session.close()


def test_package_delete(session, package):
    if not session.query(Package).filter_by(name=package.name).first():
        session.add(package)
        session.commit()
    q_package = session.query(Package).filter_by(name=package.name).first()
    session.delete(q_package)
    session.commit()
    q_package = session.query(Package).filter_by(name=package.name).first()
    assert q_package is None
    session.close()


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_db_models.py"])
