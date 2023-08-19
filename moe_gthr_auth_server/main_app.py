from typing import Literal
import click
import logging
from flask import Blueprint, Response, jsonify, request, Flask

from .err_handlrs import bad_request, unauthorized, not_found, unsupported_media_type

from .database_ops import (
    Admin,
    DBOperationResult,
    Kullanici,
    Paket,
    PaketIcerik,
    add_admin,
    add_paket,
    add_paket_icerik,
    add_user,
    db,
    girisHata,
    pIcerik,
    sha256_hash,
    try_login,
)

from werkzeug.exceptions import UnsupportedMediaType

main_blueprint = Blueprint("page", __name__, cli_group=None)


class ReqDataErrors(Exception):
    class req_data_is_none_or_empty(Exception):
        pass

    class req_data_incomplete(Exception):
        pass


LOGGER = logging.getLogger("main_blueprint")


@main_blueprint.cli.command("initdb")
@click.option("--recreate", is_flag=True, help="delete old database if exists")
def initdb_command(recreate: bool = False):
    """
    initialize database
    and delete old database if exists
    """
    from pprint import pprint
    from sqlalchemy import inspect

    print("veritabanı temel verisi oluşturuluyor")
    if ("admins" not in inspect(db.get_engine()).get_table_names()) and (not recreate):
        db.drop_all()

        ask_for_confirmation = input("‼ eski veritabani tablolari bulundu‼ \neski veritabanı silinsin mi? (y/n) : ")
        if ask_for_confirmation == "y":
            print(" ✅ eski veritabanı silindi ✅ ")
            recreate = True
        else:
            print(" ❌ eski veritabanı silinmedi ❌ ")
            return

    if recreate:
        print("eski veritabani droplanıyor")
        db.drop_all()

    db.create_all()
    print(" ✅ veritabanı tablolari oluşturuldu ✅ ")
    print("veritabanı içeriği oluşturuluyor")
    print("admin ekleniyor")
    add_admin(Admin(a_adi="mal1kc", a_sifre_hash=sha256_hash("admin")))
    print(" ☑ admin eklendi")
    db.session.commit()

    print("temel paket icerikler ekleniyor")
    for paket_icerik_deger in pIcerik:
        p_icerik = PaketIcerik(
            p_icerikAd=paket_icerik_deger,
            p_icerikDeger=pIcerik[paket_icerik_deger],
        )
        add_paket_icerik(p_icerik)
    print(" ☑ temel paket icerikler eklendi")
    print("temel paketler ekleniyor")
    add_paket(
        Paket(
            p_ad="moe_gatherer",
            p_icerikler=[
                PaketIcerik.query.filter_by(p_icerikAd=pIcerik.moe_gatherer).first(),
            ],
            p_gun=60,
        )
    )
    add_paket(
        Paket(
            p_ad="moe_gatherer+eksra_kullanici",
            p_icerikler=[
                PaketIcerik.query.filter_by(p_icerikAd=pIcerik.moe_gatherer).first(),
                PaketIcerik.query.filter_by(p_icerikAd=pIcerik.extra_user).first(),
            ],
            p_gun=60,
        ),
    )
    print(" ☑ temel paket eklendi")
    db.session.commit()
    db_paketler = [paket.__json__() for paket in Paket.query.all()]
    db_paket_icerikleri = [paket_icerik.__json__() for paket_icerik in PaketIcerik.query.all()]
    db_kullanicilar = [kullanici.__json__() for kullanici in Kullanici.query.all()]
    db_adminler = [admin.__json__() for admin in Admin.query.all()]
    print("veritabanı oluşturuldu")
    print("veritabanı içeriği : ")
    print("paketler ->")
    pprint(db_paketler)
    print("paket İçerikleri ->")
    pprint(db_paket_icerikleri)
    print("kullanıcılar ->")
    pprint(db_kullanicilar)
    print("adminler ->")
    pprint(db_adminler)


@main_blueprint.cli.command("resetdb")
def resetdb_command():
    """
    reset database to default
    """
    click.Context(main_blueprint.cli).invoke(initdb_command, recreate=True)


@main_blueprint.route("/", methods=["GET", "POST"])
def anasayfa():
    return jsonify({"status": "OK"})


@main_blueprint.route("/p_kayit", methods=["GET", "POST"])
def p_kayit() -> tuple[Response, int]:
    """
    paket and paket_icerik kayıt

    """
    ...


@main_blueprint.route("/k_kayit", methods=["GET", "POST"])
def k_kayit() -> tuple[Response, int]:
    if request.method == "POST":
        if admin := is_admin(request=request):
            if admin == "bad_request":
                return bad_request()
            try:
                req_data = request.get_json(cache=False)
                if not req_data:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if "k_ad" not in req_data or "k_sifre" not in req_data:
                    raise ReqDataErrors.req_data_incomplete()
                if req_data["k_ad"] is None or req_data["k_sifre"] is None:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if req_data["k_ad"] == "" or req_data["k_sifre"] == "":
                    raise ReqDataErrors.req_data_is_none_or_empty()

            except ReqDataErrors.req_data_incomplete:
                return jsonify({"status": "error", "message": "req_data_incomplete"}), 400
            except ReqDataErrors.req_data_is_none_or_empty:
                return jsonify({"status": "error", "message": "req_data_is_none_or_empty"}), 400
            except Exception as e:
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
            else:
                db_op_result = add_user(Kullanici(k_ad=req_data["k_ad"], k_sifre_hash=req_data["k_sifre"]))
                match db_op_result:
                    case DBOperationResult.success:
                        return (
                            jsonify({"status": "success", "message": "user_created"}),
                            200,
                        )
                    case DBOperationResult.model_already_exists:
                        return (
                            jsonify({"status": "error", "message": "user_already_exists"}),
                            200,
                        )
                    case DBOperationResult.unknown_error:
                        return (
                            jsonify({"status": "error", "message": "cannot_add_user"}),
                            200,
                        )
                    case _:
                        return jsonify({"status": "error", "message": "unknown_error"}), 200
        return unauthorized()
    else:
        if admin := is_admin(request=request):
            if admin == "bad_request":
                return bad_request()
            all_users = [kullanici.__json__() for kullanici in Kullanici.query.all()]
            all_packets = [paket.__json__() for paket in Paket.query.all()]
            all_packet_contents = [paket_icerik.__json__() for paket_icerik in PaketIcerik.query.all()]
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "db_content",
                        "users": all_users,
                        "packets": all_packets,
                        "packet_contents": all_packet_contents,
                    }
                ),
                200,
            )
    return bad_request()


@main_blueprint.route("/giris", methods=["GET", "POST"])
def giris() -> tuple[Response, int]:
    if request.method == "POST":
        if (is_user := get_user_from_req(request)) is not None and is_user is not False:
            if (girisDurumu := try_login(is_user, ip_addr=request.remote_addr)) is not None:
                if girisDurumu is girisHata.maksimum_online_kullanici:
                    return (
                        jsonify({"status": "error", "message": "maximum_online_user_quota"}),
                        401,
                    )
                elif girisDurumu is girisHata.kullanici_bulunamadi:
                    return (
                        jsonify({"status": "error", "message": "user_not_found"}),
                        404,
                    )
                elif girisDurumu is girisHata.paket_bulunamadi:
                    return (
                        jsonify({"status": "error", "message": "packet_not_found"}),
                        404,
                    )
                elif girisDurumu is girisHata.paket_suresi_bitti:
                    return (
                        jsonify({"status": "error", "message": "packet_time_expired"}),
                        410,
                    )
                elif girisDurumu is True:
                    return (
                        jsonify({"status": "success", "message": "user_logged_in"}),
                        200,
                    )
            return jsonify({"status": "error", "message": "login_failed"}), 200
        return jsonify({"status": "error", "message": "user_cred_not_found"}), 404
    return unauthorized()


def get_user_from_req(request) -> bool | Kullanici | None:
    if request.headers.get("Authorization") is None:
        return None
    else:
        user = Kullanici.query.filter_by(k_ad=request.authorization.username).first()
        if user is None:
            return False
        if request.authorization.password != user.k_sifre_hash:
            return False
        else:
            return user


def is_admin(request) -> bool | Literal["bad_request"]:
    if request.headers.get("Authorization") is None:
        return "bad_request"
    else:
        admin = Admin.query.filter_by(a_adi=request.authorization.username).first()
        if admin is None:
            return False
        if request.authorization.password != admin.a_sifre_hash:
            return False
        else:
            return True
