import random
from hashlib import sha256

import context  # pylint: disable=unused-import
from pytest import fixture
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from moe_gthr_auth_server.database_ops import (Admin, Base, K_Paket, Kullanici,
                                               Paket, PaketIcerik, add_admin,
                                               add_user, pIcerik)

test_db_engine = create_engine("sqlite:///:memory:")
test_user_data = {"k_adi": "test_user"}
test_admin_data = {"a_adi": "test_admin"}


@fixture(scope="session", autouse=True)
def _init_db():
    test_db_engine.connect()
    test_db_engine.clear_compiled_cache()
    Base.metadata.drop_all(test_db_engine)
    Base.metadata.create_all(test_db_engine)


@fixture
def user() -> Kullanici:
    return Kullanici(k_adi=test_user_data["k_adi"], k_sifre_hash=sha256(test_user_data["k_adi"].encode()).hexdigest())


@fixture
def session():
    return sessionmaker(bind=test_db_engine)()


def test_user_add(user, session):
    add_user(user, session)
    assert user == session.query(Kullanici).filter_by(k_adi=test_user_data["k_adi"]).first()
    session.close()


def test_user_password_hash(user, session):
    add_user(user, session)
    q_user = session.query(Kullanici).filter_by(k_adi=test_user_data["k_adi"]).first()
    assert q_user.k_sifre_hash == sha256(test_user_data["k_adi"].encode()).hexdigest()
    session.close()


def test_get_user_by_id(user, session):
    add_user(user, session)
    q_user = session.query(Kullanici).filter_by(k_adi=test_user_data["k_adi"]).first()
    assert q_user == session.query(Kullanici).filter_by(k_id=q_user.k_id).first()
    session.close()


@fixture
def admin() -> Admin:
    return Admin(a_adi=test_admin_data["a_adi"], a_sifre_hash=sha256(test_admin_data["a_adi"].encode()).hexdigest())


def test_admin_add(session, admin):
    add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(a_adi=test_admin_data["a_adi"]).first()
    assert q_admin == admin
    session.close()


def test_admin_password_hash(session, admin):
    add_admin(admin, session)
    q_admin = session.query(Admin).filter_by(a_adi=test_admin_data["a_adi"]).first()
    assert q_admin.a_sifre_hash == sha256(test_admin_data["a_adi"].encode()).hexdigest()
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


def test_paket_delete(session, paket):
    session.add(paket)
    session.commit()
    session.delete(paket)
    session.commit()
    q_paket = session.query(Paket).filter_by(p_ad=paket.p_ad).first()
    assert q_paket is None
    session.close()


@fixture
def paket_icerik(paket, session):
    session.add(paket)
    session.commit()
    paket = session.query(Paket).filter_by(p_ad=paket.p_ad).first()
    return PaketIcerik(p_paket_id=paket.p_id, p_icerikAd="test_paket_icerik", p_icerikDeger=pIcerik.moe_gatherer)


def test_paket_icerik_add(session, paket, paket_icerik):
    session.add(paket_icerik)
    session.commit()
    session.add(paket)
    session.commit()
    q_paket_icerik = session.query(PaketIcerik).filter_by(p_paket_id=paket.p_id).first()
    assert q_paket_icerik == paket_icerik
    session.close()


def test_paket_add_random_paket_icerik(session, paket):
    session.add(paket)
    session.commit()
    p_icerik_deger = random.choice([pi for pi in pIcerik])
    paket_icerik = PaketIcerik(p_paket_id=paket.p_id, p_icerikAd=f"test_paket_icerik_{p_icerik_deger}", p_icerikDeger=p_icerik_deger)
    q_paket_icerik = session.query(PaketIcerik).filter_by(p_id=paket.p_id).first()
    assert q_paket_icerik == paket_icerik
    session.close()


if __name__ == "__main__":
    import pytest

    pytest.main()
