from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer
from sqlalchemy import String
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column,relationship,declarative_base
from flask_sqlalchemy import SQLAlchemy

Base = declarative_base()
db = SQLAlchemy(model_class=Base)

class PaketIcerik(Base):
    __tablename__ = 'paket_icerikleri'
    p_icerikId : Mapped[int] =  mapped_column(primary_key=True,autoincrement=True)
    p_icerikAdi : Mapped[str] = mapped_column(String(256),unique=True,nullable=False)

class Paket(Base):
    __tablename__ = 'paketler'
    p_turId : Mapped[int] = mapped_column(primary_key=True,autoincrement=True)
    p_adi : Mapped[str] = mapped_column(String(256),unique=True,nullable=False)
    # p_icerik :  Mapped[list["PaketIcerik"]] = relationship(back_populates="paketler")
    p_icerik : Mapped[int] = mapped_column(ForeignKey("paket_icerikleri.p_icerikId"),nullable=True)
    p_gun : Mapped[int] = mapped_column(nullable=False)

class K_Paket(Base):
    __tablename__ = 'kullanici_paketleri'
    k_pId: Mapped[int] =  mapped_column(primary_key=True,autoincrement=True)
    k_pTur : Mapped[int] = mapped_column(ForeignKey("paketler.p_turId"),nullable=True)
    k_pBaslangic: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.utcnow())
    k_pBitis : Mapped[datetime] = mapped_column(DateTime, nullable=False)

class Kullanici(Base):
    __tablename__ = 'kullanicilar'
    k_id: Mapped[int] =  mapped_column(primary_key=True,autoincrement=True)
    k_adi : Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    k_sifre_hash : Mapped[str] = mapped_column(String(256), unique=False,nullable=False)
    k_pler : Mapped[int] = mapped_column(ForeignKey("kullanici_paketleri.k_pId"),nullable=True)
    
    def __repr__(self):
        return '<Kullanici (id:%d, k_adi:%s, k_sifre_hash:%s)>' % (self.k_id,self.k_adi,self.k_sifre_hash)
    
class Admin(Base):
    __tablename__ = 'adminler'
    a_id: Mapped[int] =  mapped_column(primary_key=True,autoincrement=True)
    a_adi : Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    a_sifre_hash : Mapped[str] = mapped_column(String(256), unique=False,nullable=False)

    def __repr__(self):
        return '<Admin (id:%d, a_adi:%s, a_sifre_hash:%s)>' % (self.a_id,self.a_adi,self.a_sifre_hash)
    

def sha256_hash(s:str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def check_password(sifre:str,hash:str) -> bool:
    return sha256_hash(sifre) == hash

def add_user(k_adi:str,k_sifre:str) -> bool:
    try:
        db.session.add(Kullanici(k_adi=k_adi,k_sifre_hash=sha256_hash(k_sifre)))
        db.session.commit()
        return True
    except Exception as e:
        print(e)
        return False

def add_admin(a_adi:str,a_sifre:str) -> bool:
    try:
        db.session.add(Admin(a_adi=a_adi,a_sifre_hash=sha256_hash(a_sifre)))
        db.session.commit()
        return True
    except Exception as e:
        print(e)
        return False

def get_user(k_adi:str) -> Kullanici:
    return db.session.query(Kullanici).filter_by(k_adi=k_adi).first()

def get_admin(a_adi:str) -> Admin:
    return db.session.query(Admin).filter_by(a_adi=a_adi).first()

def get_user_by_id(k_id:int) -> Kullanici:
    return db.session.query(Kullanici).filter_by(k_id=k_id).first()

def get_admin_by_id(a_id:int) -> Admin:
    return db.session.query(Admin).filter_by(a_id=a_id).first()