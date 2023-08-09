from datetime import datetime
from functools import wraps
from flask import Flask, session, request, redirect, url_for, flash, send_from_directory
from passlib.hash import sha256_crypt
from flask.templating import render_template
from flask_sqlalchemy import SQLAlchemy
from pathlib import Path
import os
from sqlalchemy import DateTime, ForeignKey
from sqlalchemy import String
from sqlalchemy.sql import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column,relationship

app = Flask("moe_gatherer_serv")
app.config.from_mapping(
    SECRET_KEY="secret key",
    SQLALCHEMY_DATABASE_URI="sqlite:///sunucu.db"
)

db = SQLAlchemy(app=app)

class PaketIcerik(db.Model):
  p_icerikId : Mapped[int] =  mapped_column(primary_key=True)
  p_icerikAdi : Mapped[str] = mapped_column(String(256),unique=True,nullable=False)

class Paket(db.Model):
  p_turId : Mapped[int] = mapped_column(primary_key=True)
  p_adi : Mapped[str] = mapped_column(String(256),unique=True,nullable=False)
  p_icerik :  Mapped[list["PaketIcerik"]] = relationship(back_populates="Paketler")
  p_gun : Mapped[int] = mapped_column(nullable=False)

class K_Paket(db.Model):
  k_pId: Mapped[int] =  mapped_column(primary_key=True)
  k_pTur : Mapped[int] = mapped_column(ForeignKey("Paket"))
  k_pBaslangic: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.utcnow())
  k_pBitis : Mapped[datetime] = mapped_column(DateTime, nullable=False)

class Kullanici(db.Model):
  k_id: Mapped[int] =  mapped_column(primary_key=True)
  k_adi : Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
  k_sifre_hash : Mapped[str] = mapped_column(String(256), unique=False,nullable=False)
  k_pler : Mapped[int] = mapped_column(ForeignKey("K_Paket"))
  
  def __repr__(self):
      return '<Kullanici %r>' % self.k_adi
  
      
@app.route("/")
def anasayfa():
  db.create_all()
  return "İzinsiz giriş"

if __name__ == "__main__":
  app.run(debug=True)