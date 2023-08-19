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
    # sifre_veya_kullanici_adi_yanlis = enum.auto()
    maksimum_online_kullanici = enum.auto()
    kullanici_bulunamadi = enum.auto()
    paket_bulunamadi = enum.auto()
    paket_suresi_bitti = enum.auto()
    ip_adresi_bulunamadi = enum.auto()


class DBOperationResult(enum.Enum):
    success = True
    unknown_error = enum.auto()
    model_already_exists = enum.auto()
    model_not_found = enum.auto()
    model_not_created = enum.auto()
    model_not_updated = enum.auto()
    model_not_deleted = enum.auto()


paket_icerik_paketler_bglnti_tablosu = db.Table(
    "paket_icerik_paketler_bglnti",
    db.Column("paket_icerik_id", db.Integer, db.ForeignKey("paket_icerikleri.p_icerikId")),
    db.Column("paket_id", db.Integer, db.ForeignKey("paketler.p_id")),
)


class PaketIcerik(Base):
    __tablename__ = "paket_icerikleri"
    p_icerikId: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    p_icerikAd: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    p_icerikDeger: Mapped[str] = mapped_column(Enum(*[e for e in pIcerik]), nullable=False)
    p_paketId: Mapped[int | None] = mapped_column(ForeignKey("paketler.p_id"), nullable=True)
    p_paketler: Mapped[List[Paket]] = relationship(
        "Paket", secondary=paket_icerik_paketler_bglnti_tablosu, back_populates="p_icerikler"
    )

    def __repr__(self):
        return f"<PaketIcerik ({self.p_icerikId} {self.p_icerikAd} {self.p_icerikDeger} {self.p_paketler})>"

    def __json__(self):
        return {
            "p_icerikId": self.p_icerikId,
            "p_icerikAd": self.p_icerikAd,
            "p_icerikDeger": self.p_icerikDeger,
            "p_paket_id": self.p_paketId,
            "p_paketler": self.p_paketler,
        }

    @staticmethod
    def from_json(data: dict) -> PaketIcerik:
        PaketIcerik.validate(data=data)
        return PaketIcerik(
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


class Paket(Base):
    __tablename__ = "paketler"
    p_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    p_ad: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    p_icerikler: Mapped[List[PaketIcerik]] = relationship(
        "PaketIcerik", back_populates="p_paketler", secondary=paket_icerik_paketler_bglnti_tablosu
    )
    p_gun: Mapped[int] = mapped_column(nullable=False, default=30)  # 1,30,90,365 gibi
    p_aciklama: Mapped[str] = mapped_column(String(256), nullable=False, default="paket_aciklama")

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

    @staticmethod
    def from_json(data: dict) -> Paket:
        Paket.validate(data=data)
        return Paket(
            p_ad=data["p_ad"],
            p_gun=data["p_gun"],
            p_aciklama=data["p_aciklama"],
            p_icerikler=data["p_icerikler"] if "p_icerikler" in data else None,
        )

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "p_ad": And(str, len),
                "p_gun": And(int, Use(lambda x: x in range(1, 366))),  # 1,30,90,365 gibi
                "p_aciklama": And(str, len),
                Optional("p_icerikler"): And(list, Use(lambda x: [PaketIcerik.validate(i) for i in x])),
            }
        )
        schema.validate(data)


class K_Paket(Base):
    __tablename__ = "kullanici_paketleri"
    k_pId: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    k_pTurId: Mapped[int] = mapped_column(ForeignKey("paketler.p_id"), nullable=False)
    k_pTur: Mapped[Paket] = relationship("Paket", uselist=False, backref="p_kullaniciPaketleri")
    k_pBaslangic: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    k_pBitis: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    k_pKullaniciId: Mapped[int] = mapped_column(ForeignKey("kullanicilar.k_id"), nullable=False)

    def __repr__(self) -> str:
        return f"<K_Paket {self.k_pId} {self.k_pTur} {self.k_pBaslangic} {self.k_pBitis} {self.k_pKullanici}>"

    def __json__(self):
        return {
            "k_pId": self.k_pId,
            "k_pTur": self.k_pTur,
            "k_pBaslangic": self.k_pBaslangic,
            "k_pBitis": self.k_pBitis,
            "k_pKullanici": self.k_pKullanici,
        }

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "k_pTurId": And(int, Use(paket_id_check)),
                "k_pBaslangic": And(datetime),
                "k_pBitis": And(datetime),
                "k_pKullaniciId": And(
                    int,
                    Use(kullanici_id_check),
                ),
            }
        )
        schema.validate(data)


class K_Oturum(Base):
    __tablename__ = "kullanici_oturumlari"
    k_oId: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    k_oKullaniciId: Mapped[int] = mapped_column(ForeignKey("kullanicilar.k_id"), nullable=False)
    k_oBaslangic: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    k_oBitis: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    k_oIp: Mapped[str] = mapped_column(String(256), nullable=False)
    k_oErisim: Mapped[bool] = mapped_column(nullable=False, default=True)

    def __repr__(self) -> str:
        return f"<K_Oturum {self.k_oId} {self.k_oKullanici} {self.k_oBaslangic} {self.k_oBitis} {self.k_oIp} {self.k_oErisim}>"

    def __json__(self):
        return {
            "k_oId": self.k_oId,
            "k_oKullanici": self.k_oKullanici,
            "k_oBaslangic": self.k_oBaslangic,
            "k_oBitis": self.k_oBitis,
            "k_oIp": self.k_oIp,
            "k_oErisim": self.k_oErisim,
        }

    def validate(data: dict) -> None:
        schema = Schema(
            {
                "k_oKullaniciId": And(int, Use(kullanici_id_check)),
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


class Kullanici(Base):
    __tablename__ = "kullanicilar"
    k_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    k_ad: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    k_sifre_hash: Mapped[str] = mapped_column(String(256), unique=False, nullable=False)
    k_paket: Mapped[K_Paket] = relationship("K_Paket", uselist=False, cascade="all, delete", backref="k_pKullanici")
    k_oturumlar: Mapped[List[K_Oturum]] = relationship("K_Oturum", backref="k_oKullanici")
    # k_acik_oturumlar: Mapped[List[K_Oturum]] = relationship("K_Oturum", backref="k_oKullanici")
    # 162623161333055489 gibi 18 karakterli str # TODO: ileride discord id ile oturum + discord botu ile entegre edilebilir
    k_discord_id: Mapped[str] = mapped_column(String(18), nullable=True)

    def __repr__(self):
        return "<Kullanici (id:%s, k_ad:%s, k_sifre_hash:%s)>" % (
            self.k_id,
            self.k_ad,
            self.k_sifre_hash,
        )

    def __json__(self):
        return {
            "k_id": self.k_id,
            "k_ad": self.k_ad,
            "k_sifre_hash": self.k_sifre_hash,
            "k_discord_id": self.k_discord_id,
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

    def oturum_ac(self, ip_addr: str) -> girisHata | bool:
        self.k_oturumlar.sort(key=lambda x: x.k_oBitis)
        self.k_acik_oturumlar = list(filter(lambda x: x.k_oErisim, self.k_oturumlar))
        u_paket = self.k_paket
        if u_paket is not None:
            if u_paket.k_pBitis < datetime.utcnow():
                db.session.delete(u_paket)
                db.session.commit()
                return girisHata.paket_suresi_bitti
            p_icerikleri = u_paket.k_pTur.p_icerikler
            extra_user_quota = list(filter(lambda x: x.p_icerikDeger == pIcerik.extra_user, p_icerikleri))
            max_oturum = 1 + len(extra_user_quota) if extra_user_quota is not None else 0
            ayni_ip_sbitmis_oturum = self._suresi_bitmis_acik_oturumlari_ele(ip_addr)

            if len(self.k_acik_oturumlar) >= max_oturum:
                return girisHata.maksimum_online_kullanici
            if ayni_ip_sbitmis_oturum is not None:
                ayni_ip_sbitmis_oturum.oturumu_uzat()
                db_logger.info("kullanici oturum uzatildi: id:%s, k_ad:%s, ip:%s" % (self.k_id, self.k_ad, ip_addr))
                return True
            self._acik_oturum_ekle(ip_addr)
            db.session.commit()
            db_logger.info("kullanici oturum acildi: id:%s, k_ad:%s" % (self.k_id, self.k_ad))
            return True
        return girisHata.paket_bulunamadi

    def _acik_oturum_ekle(self, ip_addr: str) -> None:
        yeni_oturum = K_Oturum(
            k_oKullaniciId=self.k_id,
            k_oBitis=datetime.utcnow() + timedelta(minutes=USER_SESSION_TIMEOUT),
            k_oIp=ip_addr,
        )
        self.k_oturumlar.append(yeni_oturum)
        self.k_acik_oturumlar.append(yeni_oturum)
        db.session.commit()

    def _suresi_bitmis_acik_oturumlari_ele(self, ip_addr: str) -> None | K_Oturum:
        """
        acik oturumlar listesini gunceller
        if ayni ip adresinden birden fazla oturum varsa en yeni olanı döndürür
        :param ip_addr: ip adresi
        :return: None | K_Oturum
        """
        suresi_bitmis_oturumlar = filter_list(lambda x: x.k_oBitis < datetime.utcnow(), self.k_acik_oturumlar)
        ayni_ip_suresi_bitmis_oturumlar = filter_list(lambda x: x.k_oIp == ip_addr, suresi_bitmis_oturumlar)
        diger_ip_suresi_bitmis_oturumlar = filter_list(lambda x: x.k_oIp != ip_addr, suresi_bitmis_oturumlar)
        self._oturumlari_kapat(diger_ip_suresi_bitmis_oturumlar)

        if len(ayni_ip_suresi_bitmis_oturumlar) > 1:
            ayni_ip_suresi_bitmis_oturumlar.sort(key=lambda x: x.k_oBitis)
            secilimis_oturum = ayni_ip_suresi_bitmis_oturumlar[0]
            self.ayni_ip_suresi_bitmis_oturumlar.remove(secilimis_oturum)
            self._oturumlari_kapat(ayni_ip_suresi_bitmis_oturumlar)
            return secilimis_oturum
        return None

    def _oturumu_kapat(self, oturum: K_Oturum) -> None:
        oturum.k_oErisim = False
        db_logger.info("kullanici oturum kapatildi: id:%s, k_ad:%s" % (self.k_id, self.k_ad))
        self.k_acik_oturumlar.remove(oturum)
        self.k_oturumlar.append(oturum)

    def _oturumlari_kapat(self, oturumlar: List[K_Oturum]) -> None:
        if oturumlar is not None:
            for oturum in oturumlar:
                self._oturumu_kapat(oturum)
        db.session.commit()

    def tum_oturumlari_kapat(self) -> None:
        if self.k_oturumlar is not None:
            for oturum in self.k_oturumlar:
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


def add_user(kullanici: Kullanici, session: scoped_session = db.session) -> DBOperationResult:
    try:
        with session.begin_nested():
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


def add_paket(paket: Paket, session: scoped_session = db.session) -> DBOperationResult:
    try:
        session.add(paket)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding paket to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("paket already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_paket_icerik(paket_icerik: PaketIcerik, session: scoped_session = db.session) -> DBOperationResult:
    try:
        session.add(paket_icerik)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding paket_icerik to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("paket_icerik already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_k_paket(k_paket: K_Paket, session: scoped_session = db.session) -> DBOperationResult:
    try:
        session.add(k_paket)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while adding k_paket to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            db_logger.error("k_paket already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def update_user(k_id: str, new_kullanici: Kullanici, session: scoped_session = db.session) -> DBOperationResult:
    """
    update kullanici with k_id
    :param k_id: id of kullanici to update
    :param new_kullanici: new kullanici object
    :param session: db session
    :return: DBOperationResult
    ---
    only update k_ad, k_sifre_hash, k_discord_id, k_pler
    ---
    """
    try:
        db_kullanici = session.query(Kullanici).filter_by(k_id=k_id).first()
        if db_kullanici is None:
            return DBOperationResult.model_not_found
        if new_kullanici.k_ad is not None:
            db_kullanici.k_ad = new_kullanici.k_ad
        if new_kullanici.k_sifre_hash is not None:
            db_kullanici.password_hash = new_kullanici.password_hash
        if new_kullanici.k_discord_id is not None:
            db_kullanici.k_discord_id = new_kullanici.k_discord_id
        if new_kullanici.k_pler is not None:
            db_kullanici.k_pler = new_kullanici.k_pler
        # TODO: check if this works
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        db_logger.error("error accured while updating kullanici to database %s" % e)
    return DBOperationResult.unknown_error


def get_user(k_ad: str, session: scoped_session = db.session) -> Kullanici:
    return session.query(Kullanici).filter_by(k_ad=k_ad).first()


def get_admin(a_adi: str, session: scoped_session = db.session) -> Admin:
    return session.query(Admin).filter_by(a_adi=a_adi).first()


def get_user_by_id(k_id: int, session: scoped_session = db.session) -> Kullanici:
    return session.query(Kullanici).filter_by(k_id=k_id).first()


def get_admin_by_id(a_id: int, session: scoped_session = db.session) -> Admin:
    return session.query(Admin).filter_by(a_id=a_id).first()


def try_login(user: Kullanici, ip_addr: str | None) -> girisHata | bool:
    if ip_addr is None:
        return girisHata.ip_adresi_bulunamadi
    if user is not None:
        return user.oturum_ac(ip_addr)
    return girisHata.kullanici_bulunamadi


def filter_list(function: Callable[[Any], bool], input_list: List[Any]) -> List[Any]:
    return list(filter(function, input_list))


def __paket_id_check(paket_id: int) -> bool:
    if paket_id in [paket.p_id for paket in Paket.query.all()]:
        return True
    return False


def __kullanici_id_check(kullanici_id: int) -> bool:
    if kullanici_id in [kullanici.k_id for kullanici in Kullanici.query.all()]:
        return True
    return False


def validate_data_schema(cls, data):
    try:
        cls.validate(data)
    except SchemaError as e:
        raise e
