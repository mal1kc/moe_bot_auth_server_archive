from __future__ import annotations
import enum
from datetime import datetime, timedelta
from logging import getLogger
from typing import Any, Callable, List
from .config.flask import USER_OLDEST_SESSION_TIMEOUT, USER_SESSION_TIMEOUT

from flask_sqlalchemy import SQLAlchemy
from schema import Schema, And, Use, Optional, SchemaError
from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, declarative_base, mapped_column, relationship, scoped_session
from sqlalchemy.orm.decl_api import DeclarativeMeta

Base: DeclarativeMeta = declarative_base()
db = SQLAlchemy(model_class=Base)
db_logger = getLogger("sqlalchemy_db")


class pIcerik(enum.StrEnum):
    # TODO : maybe change in future for more flexibility
    moe_gatherer = enum.auto()  # -> "moe_gatherer"
    moe_advantures = enum.auto()
    moe_camp = enum.auto()
    moe_arena = enum.auto()
    moe_raid = enum.auto()
    extra_user = enum.auto()
    discord = enum.auto()  # TODO: discord api kullanım hakkı


class girisHata(enum.IntEnum):
    # sifre_veya_user_adi_yanlis = enum.auto()
    maksimum_online_user = enum.auto()
    user_bulunamadi = enum.auto()
    package_bulunamadi = enum.auto()
    package_suresi_bitti = enum.auto()
    inameresi_bulunamadi = enum.auto()


class DBOperationResult(enum.Enum):
    success = True
    unknown_error = enum.auto()
    model_already_exists = enum.auto()
    model_not_found = enum.auto()
    model_not_created = enum.auto()
    model_not_updated = enum.auto()
    model_not_deleted = enum.auto()


package_content_packageler_bglnti_tablosu = db.Table(
    "package_content_packageler_bglnti",
    db.Column("package_content_id", db.Integer, db.ForeignKey("package_contentleri.p_icerikId")),
    db.Column("package_id", db.Integer, db.ForeignKey("packageler.p_id")),
)


class PackageIcerik(Base):
    __tablename__ = "package_contentleri"
    p_icerikId: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    p_icerikAd: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    p_icerikDeger: Mapped[str] = mapped_column(Enum(*[e for e in pIcerik]), nullable=False)
    p_packageId: Mapped[int | None] = mapped_column(ForeignKey("packageler.p_id"), nullable=True)
    p_packageler: Mapped[List[Package]] = relationship(
        "Package", secondary=package_content_packageler_bglnti_tablosu, back_populates="p_icerikler"
    )

    def __repr__(self):
        return f"<PackageIcerik ({self.p_icerikId} {self.p_icerikAd} {self.p_icerikDeger} {self.p_packageler})>"

    def __json__(self):
        return {
            "p_icerikId": self.p_icerikId,
            "p_icerikAd": self.p_icerikAd,
            "p_icerikDeger": self.p_icerikDeger,
            "p_package_id": self.p_packageId,
            "p_packageler": self.p_packageler,
        }

    @staticmethod
    def from_json(data: dict) -> PackageIcerik:
        PackageIcerik.validate(data=data)
        return PackageIcerik(
            p_icerikAd=data["p_icerikAd"],
            p_icerikDeger=data["p_icerikDeger"],
        )

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "p_icerikAd": And(str, len),
                "p_icerikDeger": And(str, Use(pIcerik)),
            }
        )
        schema.validate(data)


class Package(Base):
    __tablename__ = "packageler"
    p_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    p_icerikler: Mapped[List[PackageIcerik]] = relationship(
        "PackageIcerik", back_populates="p_packageler", secondary=package_content_packageler_bglnti_tablosu
    )
    p_gun: Mapped[int] = mapped_column(nullable=False, default=30)  # 1,30,90,365 gibi
    p_aciklama: Mapped[str] = mapped_column(String(256), nullable=False, default="package_aciklama")

    def __repr__(self):
        return f"<Package {self.p_id} {self.name} {self.p_gun} {self.p_aciklama}>"

    def __json__(self):
        return {
            "p_id": self.p_id,
            "name": self.name,
            "p_icerikler": self.p_icerikler,
            "p_gun": self.p_gun,
            "p_aciklama": self.p_aciklama,
        }

    @staticmethod
    def from_json(data: dict) -> Package:
        Package.validate(data=data)
        return Package(
            name=data["name"],
            p_gun=data["p_gun"],
            p_aciklama=data["p_aciklama"],
            p_icerikler=data["p_icerikler"] if "p_icerikler" in data else None,
        )

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "name": And(str, len),
                "p_gun": And(int, Use(lambda x: x in range(1, 366))),  # 1,30,90,365 gibi
                "p_aciklama": And(str, len),
                Optional("p_icerikler"): And(list, Use(lambda x: [PackageIcerik.validate(i) for i in x])),
            }
        )
        schema.validate(data)


class K_Package(Base):
    __tablename__ = "user_packageleri"
    k_pId: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    k_pTurId: Mapped[int] = mapped_column(ForeignKey("packageler.p_id"), nullable=False)
    k_pTur: Mapped[Package] = relationship("Package", uselist=False, backref="p_userPackageleri")
    k_pBaslangic: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    k_pBitis: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    k_pUserId: Mapped[int] = mapped_column(ForeignKey("userlar.k_id"), nullable=False)

    def __repr__(self) -> str:
        return f"<K_Package {self.k_pId} {self.k_pTur} {self.k_pBaslangic} {self.k_pBitis} {self.k_pUser}>"

    def __json__(self):
        return {
            "k_pId": self.k_pId,
            "k_pTur": self.k_pTur,
            "k_pBaslangic": self.k_pBaslangic,
            "k_pBitis": self.k_pBitis,
            "k_pUser": self.k_pUser,
        }

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "k_pTurId": And(int, Use(package_id_check)),
                "k_pBaslangic": And(datetime),
                "k_pBitis": And(datetime),
                "k_pUserId": And(
                    int,
                    Use(user_id_check),
                ),
            }
        )
        schema.validate(data)


class U_Session(Base):
    __tablename__ = "user_oturumlari"
    u_sId: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    u_sUserId: Mapped[int] = mapped_column(ForeignKey("userlar.k_id"), nullable=False)
    u_sBaslangic: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    u_sBitis: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    u_sIp: Mapped[str] = mapped_column(String(256), nullable=False)
    u_sErisim: Mapped[bool] = mapped_column(nullable=False, default=True)

    def __repr__(self) -> str:
        return f"<U_Session {self.k_oId} {self.k_oUser} {self.k_oBaslangic} {self.k_oBitis} {self.k_oIp} {self.k_oErisim}>"

    def __json__(self):
        return {
            "k_oId": self.k_oId,
            "k_oUser": self.k_oUser,
            "k_oBaslangic": self.k_oBaslangic,
            "k_oBitis": self.k_oBitis,
            "k_oIp": self.k_oIp,
            "k_oErisim": self.k_oErisim,
        }

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "k_oUserId": And(int, Use(user_id_check)),
                "k_oBaslangic": And(datetime),
                "k_oBitis": And(
                    datetime,
                ),
                "k_oIp": And(str, len),
                "k_oErisim": And(bool),
            }
        )
        schema.validate(data)

    def oturumu_uzat(self) -> None:
        self.k_oBitis = datetime.utcnow() + timedelta(minutes=USER_SESSION_TIMEOUT)
        self.k_oErisim = True
        db.session.commit()


class User(Base):
    """
    # tr:User
    db model for users
    """

    __tablename__ = "userlar"
    u_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    u_name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    u_password_hash: Mapped[str] = mapped_column(String(256), unique=False, nullable=False)
    u_package: Mapped[K_Package] = relationship("K_Package", uselist=False, cascade="all, delete", backref="k_pUser")
    u_sessions: Mapped[List[U_Session]] = relationship("U_Session", backref="k_oUser")
    # k_aciu_sessionlar: Mapped[List[K_Oturum]] = relationship("K_Oturum", backref="k_oUser")
    # 162623161333055489 gibi 18 karakterli str # TODO: ileride discord id ile oturum + discord botu ile entegre edilebilir
    u_discord_id: Mapped[str] = mapped_column(String(18), nullable=True)

    def __repr__(self):
        return "<User (id:%s, k_ad:%s, k_sifre_hash:%s)>" % (
            self.u_id,
            self.u_name,
            self.u_password_hash,
        )

    def __json__(self):
        return {
            "k_id": self.u_id,
            "k_ad": self.u_name,
            "k_sifre_hash": self.u_password_hash,
            "k_discord_id": self.u_discord_id,
        }

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "k_ad": And(str, len),
                "k_sifre_hash": And(str, len),
                Optional("k_discord_id"): And(str, len),
            }
        )
        schema.validate(data)

    def oturum_ac(self, inamedr: str) -> girisHata | bool:
        self.u_sessions.sort(key=lambda x: x.k_oBitis)
        self.k_aciu_sessionlar = list(filter(lambda x: x.k_oErisim, self.u_sessions))
        u_package = self.u_package
        if u_package is not None:
            if u_package.k_pBitis < datetime.utcnow():
                db.session.delete(u_package)
                db.session.commit()
                return girisHata.package_suresi_bitti
            p_icerikleri = u_package.k_pTur.p_icerikler
            extra_user_quota = list(filter(lambda x: x.p_icerikDeger == pIcerik.extra_user, p_icerikleri))
            max_oturum = 1 + len(extra_user_quota) if extra_user_quota is not None else 0
            ayni_ip_sbitmis_oturum = self._suresi_bitmis_aciu_sessionlari_ele(inamedr)

            if len(self.k_aciu_sessionlar) >= max_oturum:
                return girisHata.maksimum_online_user
            if ayni_ip_sbitmis_oturum is not None:
                ayni_ip_sbitmis_oturum.oturumu_uzat()
                db_logger.info("user oturum uzatildi: id:%s, k_ad:%s, ip:%s" % (self.u_id, self.u_name, inamedr))
                return True
            self._aciu_session_ekle(inamedr)
            db.session.commit()
            db_logger.info("user oturum acildi: id:%s, k_ad:%s" % (self.u_id, self.u_name))
            return True
        return girisHata.package_bulunamadi

    def _aciu_session_ekle(self, inamedr: str) -> None:
        yeni_oturum = U_Session(
            k_oUserId=self.u_id,
            k_oBitis=datetime.utcnow() + timedelta(minutes=USER_SESSION_TIMEOUT),
            k_oIp=inamedr,
        )
        self.u_sessions.append(yeni_oturum)
        self.k_aciu_sessionlar.append(yeni_oturum)
        db.session.commit()

    def _suresi_bitmis_aciu_sessionlari_ele(self, inamedr: str) -> None | U_Session:
        """
        acik oturumlar listesini gunceller
        if ayni ip adresinden birden fazla oturum varsa en yeni olanı döndürür
        :param inamedr: ip adresi
        :return: None | U_Session
        """
        suresi_bitmis_oturumlar = filter_list(lambda x: x.k_oBitis < datetime.utcnow(), self.k_aciu_sessionlar)
        ayni_ip_suresi_bitmis_oturumlar = filter_list(lambda x: x.k_oIp == inamedr, suresi_bitmis_oturumlar)
        diger_ip_suresi_bitmis_oturumlar = filter_list(lambda x: x.k_oIp != inamedr, suresi_bitmis_oturumlar)
        self._oturumlari_kapat(diger_ip_suresi_bitmis_oturumlar)

        if len(ayni_ip_suresi_bitmis_oturumlar) > 1:
            ayni_ip_suresi_bitmis_oturumlar.sort(key=lambda x: x.k_oBitis)
            secilimis_oturum = ayni_ip_suresi_bitmis_oturumlar[0]
            self.ayni_ip_suresi_bitmis_oturumlar.remove(secilimis_oturum)
            self._oturumlari_kapat(ayni_ip_suresi_bitmis_oturumlar)
            return secilimis_oturum
        return None

    def _oturumu_kapat(self, oturum: U_Session) -> None:
        oturum.k_oErisim = False
        db_logger.info("user oturum kapatildi: id:%s, k_ad:%s" % (self.u_id, self.u_name))
        self.k_aciu_sessionlar.remove(oturum)
        self.u_sessions.append(oturum)

    def _oturumlari_kapat(self, oturumlar: List[U_Session]) -> None:
        if oturumlar is not None:
            for oturum in oturumlar:
                self._oturumu_kapat(oturum)
        db.session.commit()

    def tum_oturumlari_kapat(self) -> None:
        if self.u_sessions is not None:
            for oturum in self.u_sessions:
                self._oturumu_kapat(oturum)
        db.session.commit()


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

    def validate(data: dict) -> None:
        schema = Schema({"a_adi": And(str, len), "a_sifre_hash": And(str, len)})
        schema.validate(data)


def sha256_hash(s: str) -> str:
    import hashlib

    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def check_password(sifre: str, hash: str) -> bool:
    return sha256_hash(sifre) == hash


def add_user(user: User, session: scoped_session = db.session) -> DBOperationResult:
    try:
        with session.begin_nested():
            session.add(user)
            session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding user to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("user already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_admin(admin: Admin, session: scoped_session = db.session) -> DBOperationResult:
    try:
        with session.begin_nested():
            session.add(admin)
            session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding admin to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("admin already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_package(package: Package, session: scoped_session = db.session) -> DBOperationResult:
    try:
        session.add(package)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding package to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("package already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_package_content(package_content: PackageIcerik, session: scoped_session = db.session) -> DBOperationResult:
    try:
        session.add(package_content)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding package_content to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("package_content already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_k_package(k_package: K_Package, session: scoped_session = db.session) -> DBOperationResult:
    try:
        session.add(k_package)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding k_package to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("k_package already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def update_user(k_id: str, new_user: User, session: scoped_session = db.session) -> DBOperationResult:
    """
    update user with k_id
    :param k_id: id of user to update
    :param new_user: new user object
    :param session: db session
    :return: DBOperationResult
    ---
    only update k_ad, k_sifre_hash, k_discord_id, k_pler
    ---
    """
    try:
        db_user = session.query(User).filter_by(k_id=k_id).first()
        if db_user is None:
            return DBOperationResult.model_not_found
        if new_user.u_name is not None:
            db_user.u_name = new_user.u_name
        if new_user.u_password_hash is not None:
            db_user.password_hash = new_user.password_hash
        if new_user.u_discord_id is not None:
            db_user.u_discord_id = new_user.u_discord_id
        if new_user.k_pler is not None:
            db_user.k_pler = new_user.k_pler
        # TODO: check if this works
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while updating user to database %s" % e)
    return DBOperationResult.unknown_error


def get_user(k_ad: str, session: scoped_session = db.session) -> User:
    return session.query(User).filter_by(k_ad=k_ad).first()


def get_admin(a_adi: str, session: scoped_session = db.session) -> Admin:
    return session.query(Admin).filter_by(a_adi=a_adi).first()


def get_user_by_id(k_id: int, session: scoped_session = db.session) -> User:
    return session.query(User).filter_by(k_id=k_id).first()


def get_admin_by_id(a_id: int, session: scoped_session = db.session) -> Admin:
    return session.query(Admin).filter_by(a_id=a_id).first()


def try_login(user: User, inamedr: str | None) -> girisHata | bool:
    if inamedr is None:
        return girisHata.inameresi_bulunamadi
    if user is not None:
        return user.oturum_ac(inamedr)
    return girisHata.user_bulunamadi


def filter_list(function: Callable[[Any], bool], input_list: List[Any]) -> List[Any]:
    return list(filter(function, input_list))


def __package_id_check(package_id: int) -> bool:
    if package_id in [package.p_id for package in Package.query.all()]:
        return True
    return False


def __user_id_check(user_id: int) -> bool:
    if user_id in [user.k_id for user in User.query.all()]:
        return True
    return False


def validate_data_schema(cls, data):
    try:
        cls.validate(data)
    except SchemaError as e:
        raise e
