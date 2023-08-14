from __future__ import annotations

import enum
from datetime import datetime
from logging import getLogger
from typing import List

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (Mapped, Session, declarative_base, mapped_column,
                            relationship, scoped_session)
from sqlalchemy.sql import func

Base = declarative_base()
db = SQLAlchemy(model_class=Base)
db_logger = getLogger("sqlalchemy_db")


class pIcerik(enum.StrEnum):
    moe_gatherer = "moe_gatherer"
    moe_advantures = "moe_advantures"
    moe_camp = "moe_camp"
    moe_arena = "moe_arena"
    moe_raid = "moe_raid"
    extra_user = "extra_user"
    discord = "discord_api"  # TODO: discord api kullanım hakkı


class girisHata(enum.IntEnum):
    sifre_veya_kullanici_adi_yanlis = 0
    maksimum_online_kullanici = 1
    kullanici_bulunamadi = 2
    paket_bulunamadi = 3
    paket_suresi_bitti = 4


class DBOperationResult(enum.Enum):
    success = True
    unknown_error = enum.auto()
    model_already_exists = enum.auto()
    model_not_found = enum.auto()
    model_not_created = enum.auto()
    model_not_updated = enum.auto()
    model_not_deleted = enum.auto()


class PaketIcerik(Base):
    __tablename__ = "paket_icerikleri"
    p_icerikId: Mapped[int] = mapped_column(
        primary_key=True, autoincrement=True, unique=True
    )
    p_icerikAd: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    p_icerikDeger: Mapped[str] = mapped_column(
        Enum(*[e for e in pIcerik]), nullable=False
    )
    p_paket_id: Mapped[int | None] = mapped_column(
        ForeignKey("paketler.p_id"), nullable=True
    )
    p_paketler: Mapped[List[Paket | None]] = relationship(
        "Paket", back_populates="p_icerikler"
    )

    def __repr__(self):
        return f"<PaketIcerik {self.p_icerikId} {self.p_icerikAd} {self.p_icerikDeger}>"

    def __json__(self):
        return {
            "p_icerikId": self.p_icerikId,
            "p_icerikAd": self.p_icerikAd,
            "p_icerikDeger": self.p_icerikDeger,
            "p_paket_id": self.p_paket_id,
            "p_paketler": self.p_paketler,
        }


class Paket(Base):
    __tablename__ = "paketler"
    p_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    p_ad: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    p_icerikler: Mapped[List[PaketIcerik]] = relationship(
        "PaketIcerik", back_populates="p_paketler"
    )
    p_gun: Mapped[int] = mapped_column(nullable=False, default=30)  # 1,30,90,365 gibi
    p_aciklama: Mapped[str] = mapped_column(
        String(256), nullable=False, default="paket_aciklama"
    )

    def __repr__(self):
        return f"<Paket {self.p_id} {self.p_ad} {self.p_gun} {self.p_aciklama}>"

    def __json__(self):
        return {
            "p_id": self.p_id,
            "p_ad": self.p_ad,
            "p_icerikler": self.p_icerikler,
            "p_gun": self.p_gun,
            "p_aciklama": self.p_aciklama,
        }


class K_Paket(Base):
    __tablename__ = "kullanici_paketleri"
    k_pId: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    k_pTur: Mapped[int] = mapped_column(ForeignKey("paketler.p_id"), nullable=False)
    k_pBaslangic: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    k_pBitis: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    k_pKullanici: Mapped[int] = mapped_column(
        ForeignKey("kullanicilar.k_id"), nullable=False
    )

    def __repr__(self):
        return f"<K_Paket {self.k_pId} {self.k_pTur} {self.k_pBaslangic} {self.k_pBitis} {self.k_pKullanici}>"

    def __json__(self):
        return {
            "k_pId": self.k_pId,
            "k_pTur": self.k_pTur,
            "k_pBaslangic": self.k_pBaslangic,
            "k_pBitis": self.k_pBitis,
            "k_pKullanici": self.k_pKullanici,
        }


class Kullanici(Base):
    __tablename__ = "kullanicilar"
    k_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    k_adi: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    k_sifre_hash: Mapped[str] = mapped_column(String(256), unique=False, nullable=False)
    k_paket: Mapped[int] = relationship("K_Paket", backref="kullanicilar")
    k_son_oturum_kontrol: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    k_acik_oturumlar: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, autoincrement=False
    )
    # 162623161333055489 gibi 18 karakterli str # TODO: ileride discord id ile oturum + discord botu ile entegre edilebilir
    k_discord_id: Mapped[str] = mapped_column(String(18), nullable=True)

    def __repr__(self):
        return "<Kullanici (id:%s, k_adi:%s, k_sifre_hash:%s)>" % (
            self.k_id,
            self.k_adi,
            self.k_sifre_hash,
        )

    def oturum_ac(self) -> girisHata | bool:
        u_paket = db.session.query(K_Paket).filter_by(k_pId=self.k_pler).first()
        if u_paket is not None:
            if u_paket.k_pBitis < datetime.utcnow():
                db.session.delete(u_paket)
                db.session.commit()
                return girisHata.paket_suresi_bitti
            p_icerikleri = (
                Paket.query.filter_by(p_turId=u_paket.k_pTur).first().p_icerikler
            )
            extra_user_quota = p_icerikleri.filter_by(
                p_icerikDeger=pIcerik.extra_user
            ).all()
            max_oturum = 1 + len(extra_user_quota)
            if self.k_acik_oturumlar >= max_oturum:
                return girisHata.maksimum_online_kullanici
            self.k_acik_oturumlar += 1
            db.session.commit()
            return True
        return girisHata.paket_bulunamadi

    def __json__(self):
        return {"k_id": self.k_id, "k_adi": self.k_adi}


class Admin(Base):
    __tablename__ = "adminler"
    a_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    a_adi: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    a_sifre_hash: Mapped[str] = mapped_column(String(256), unique=False, nullable=False)

    def __repr__(self):
        return "<Admin (id:%s, a_adi:%s, a_sifre_hash:%s)>" % (
            self.a_id,
            self.a_adi,
            self.a_sifre_hash,
        )

    def __json__(self):
        return {"a_id": self.a_id, "a_adi": self.a_adi}


def sha256_hash(s: str) -> str:
    import hashlib

    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def check_password(sifre: str, hash: str) -> bool:
    return sha256_hash(sifre) == hash


def add_user(
    kullanici: Kullanici, session: scoped_session = db.session
) -> DBOperationResult:
    try:
        session.add(kullanici)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding kullanici to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("kullanici already exists")
            return DBOperationResult.model_already_exists
        return DBOperationResult.unknown_error


def add_admin(admin: Admin, session: scoped_session = db.session) -> DBOperationResult:
    try:
        session.add(admin)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding admin to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("admin already exists")
            return DBOperationResult.model_already_exists
        return DBOperationResult.unknown_error


def get_user(k_adi: str, session: scoped_session = db.session) -> Kullanici:
    return session.query(Kullanici).filter_by(k_adi=k_adi).first()


def get_admin(a_adi: str, session: scoped_session = db.session) -> Admin:
    return session.query(Admin).filter_by(a_adi=a_adi).first()


def get_user_by_id(k_id: int, session: scoped_session = db.session) -> Kullanici:
    return session.query(Kullanici).filter_by(k_id=k_id).first()


def get_admin_by_id(a_id: int, session: scoped_session = db.session) -> Admin:
    return session.query(Admin).filter_by(a_id=a_id).first()


def try_login(user: Kullanici) -> girisHata | bool:
    if user is not None:
        return user.oturum_ac()
    return girisHata.kullanici_bulunamadi
