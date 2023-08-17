import logging
import random
from hashlib import sha256

import pytest
from moe_gthr_auth_server.database_ops import (
    Admin,
    Base,
    DBOperationResult,
    K_Paket,
    Kullanici,
    Paket,
    PaketIcerik,
    add_admin,
    add_user,
    pIcerik,
)
from pytest import fixture
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

test_db_engine = create_engine("sqlite:///:memory:")

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


@fixture(scope="session", autouse=True)
def _init_db():
    test_db_engine.connect()
    test_db_engine.clear_compiled_cache()
    Base.metadata.drop_all(bind=test_db_engine)
    Base.metadata.create_all(bind=test_db_engine)


@fixture
def session():
    return sessionmaker(bind=test_db_engine)()


def test_check_database_empty(session):
    assert session.query(Admin).all() == []
    assert session.query(Kullanici).all() == []
    assert session.query(Paket).all() == []
    assert session.query(PaketIcerik).all() == []
    session.close()


@fixture
def user_data():
    return {"k_ad": "test_user", "k_sifre": sha256("test_user".encode()).hexdigest()}


@fixture
def user(user_data) -> Kullanici:
    return Kullanici(
        k_ad=user_data["k_ad"],
        k_sifre_hash=sha256(user_data["k_ad"].encode()).hexdigest(),
    )


def test_user_add(user, session, user_data):
    add_user(user, session)

    assert user == session.query(Kullanici).filter_by(k_ad=user_data["k_ad"]).first()
    session.close()


def test_user_password_hash(user, session, user_data):
    add_user(user, session)
    q_user = session.query(Kullanici).filter_by(k_ad=user_data["k_ad"]).first()
    assert q_user.k_sifre_hash == sha256(user_data["k_ad"].encode()).hexdigest()
    session.close()


def test_get_user_by_id(user, session, user_data):
    add_user(user, session)
    q_user = session.query(Kullanici).filter_by(k_ad=user_data["k_ad"]).first()
    assert q_user == session.query(Kullanici).filter_by(k_id=q_user.k_id).first()
    session.close()


@fixture
def admin_data():
    return {"a_adi": "test_admin", "a_sifre": sha256("test_admin".encode()).hexdigest()}


@fixture
def admin(admin_data) -> Admin:
    return Admin(
        a_adi=admin_data["a_adi"],
        a_sifre_hash=sha256(admin_data["a_adi"].encode()).hexdigest(),
    )


def test_admin_add(admin, session, admin_data):
    if not session.query(Admin).filter_by(a_adi=admin_data["a_adi"]).first():
        add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(a_adi=admin_data["a_adi"]).first()
    assert q_admin == admin
    session.close()


def test_admin_password_hash(session, admin, admin_data):
    if not session.query(Admin).filter_by(a_adi=admin_data["a_adi"]).first():
        add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(a_adi=admin_data["a_adi"]).first()
    assert q_admin.a_sifre_hash == sha256(admin_data["a_adi"].encode()).hexdigest()
    session.close()


def test_admin_already_exists(admin, session, admin_data):
    # TODO: find cause of error when running this on its own
    if not (q_admin := session.query(Admin).filter_by(a_adi=admin_data["a_adi"]).first()):
        LOGGER.debug("test_admin_already_exists: q_admin: %s", q_admin)
        assert DBOperationResult.success == add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(a_adi=admin_data["a_adi"]).first()
    LOGGER.debug("test_admin_already_exists: after first add_admin -> q_admin: %s", q_admin)
    assert DBOperationResult.model_already_exists == add_admin(admin, session)
    q_all_admins = session.query(Admin).all()
    LOGGER.debug("test_admin_already_exists: after second add_admin -> q_all_admins: %s", q_all_admins)
    assert len(q_all_admins) == 1
    q_admin = session.query(Admin).filter_by(a_adi=admin_data["a_adi"]).first()
    assert q_admin.a_adi == admin.a_adi
    session.close()


@fixture
def paket():
    return Paket(p_ad="test_paket", p_aciklama="test_paket_aciklama", p_gun=30)


def test_paket_add(session, paket):
    session.add(paket)
    session.commit()
    q_paket = session.query(Paket).filter_by(p_ad=paket.p_ad).first()
    assert q_paket == paket
    session.close()


@fixture
def paket_icerik(paket, session):
    if not session.query(Paket).filter_by(p_ad=paket.p_ad).first():
        session.add(paket)
    session.commit()
    paket = session.query(Paket).filter_by(p_ad=paket.p_ad).first()
    return PaketIcerik(
        p_paketId=paket.p_id,
        p_icerikAd="test_paket_icerik",
        p_icerikDeger=random.choice([pi for pi in pIcerik]),
    )


def test_paket_icerik_add(session, paket, paket_icerik):
    if not session.query(Paket).filter_by(p_ad=paket.p_ad).first():
        session.add(paket)
    session.add(paket_icerik)
    session.commit()
    q_paket_icerikleri = session.query(PaketIcerik).filter(PaketIcerik.p_paketId == paket.p_id).all()
    if len(q_paket_icerikleri) == 0:
        paket = session.query(Paket).filter_by(p_ad=paket.p_ad).first()
        q_paket_icerikleri = session.query(PaketIcerik).filter(PaketIcerik.p_paketId == paket.p_id).all()
    assert paket_icerik in q_paket_icerikleri
    session.close()


def test_paket_add_random_paket_icerik(session, paket):
    if not session.query(Paket).filter_by(p_ad=paket.p_ad).first():
        session.add(paket)
        session.commit()
    p_icerik_deger = random.choice([pi for pi in pIcerik])
    paket_icerik = PaketIcerik(
        p_icerikAd=f"test_paket_icerik_{p_icerik_deger}",
        p_icerikDeger=p_icerik_deger,
        p_paketId=paket.p_id,
    )
    if not session.query(PaketIcerik).filter(PaketIcerik.p_icerikAd == paket_icerik.p_icerikAd).first():
        session.add(paket_icerik)
        session.commit()
    q_paket_icerik = session.query(PaketIcerik).filter_by(p_paketId=paket.p_id).first()
    assert q_paket_icerik == paket_icerik
    session.close()


def test_paket_delete(session, paket):
    if not session.query(Paket).filter_by(p_ad=paket.p_ad).first():
        session.add(paket)
        session.commit()
    q_paket = session.query(Paket).filter_by(p_ad=paket.p_ad).first()
    session.delete(q_paket)
    session.commit()
    q_paket = session.query(Paket).filter_by(p_ad=paket.p_ad).first()
    assert q_paket is None
    session.close()


if __name__ == "__main__":
    pytest.main(["--log-cli-level=DEBUG", "-v", "test_db_models.py"])
