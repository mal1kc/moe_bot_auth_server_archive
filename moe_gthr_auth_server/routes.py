from typing import Literal

from flask import Blueprint, Response, jsonify, request, Flask

from .err_handlrs import bad_request, not_found, unsupported_media_type

from .database_ops import Admin, DBOperationResult, Kullanici, Paket, PaketIcerik, add_user, db, girisHata, sha256_hash, try_login

from werkzeug.exceptions import UnsupportedMediaType

main_blueprint = Blueprint("page", __name__)


class ReqDataErrors(Exception):
    class req_data_is_none_or_empty(Exception):
        pass

    class req_data_incomplete(Exception):
        pass


@main_blueprint.cli.command("initdb")
def initdb_command():
    print("Veritabanı oluşturuluyor")
    db.create_all()
    print("Veritabanı oluşturuldu")
    if Kullanici.query.filter_by(k_adi="mal1kc").first() is None:
        db.session.add(Kullanici(k_adi="mal1kc", k_sifre_hash=sha256_hash("admin")))
    print("Admin eklendi")
    db.session.commit()
    print("Veritabanı oluşturuldu")


@main_blueprint.cli.command("resetdb")
def resetdb_command():
    print("Veritabanı siliniyor")
    db.drop_all()
    print("Veritabanı silindi")
    print("Veritabanı oluşturuluyor")
    db.create_all()
    print("Veritabanı oluşturuldu")
    if Kullanici.query.filter_by(k_adi="mal1kc").first() is None:
        db.session.add(Kullanici(k_adi="mal1kc", k_sifre_hash=sha256_hash("admin")))
    print("Admin eklendi")
    db.session.commit()
    print("Veritabanı oluşturuldu")


@main_blueprint.route("/", methods=["GET", "POST"])
def anasayfa():
    return jsonify({"status": "OK"})


@main_blueprint.route("/kayit", methods=["GET", "POST"])
def kayit() -> tuple[Response, int]:
    if request.method == "POST":
        if admin := is_admin(request=request):
            if admin == "bad_request":
                return bad_request()
            try:
                req_data = request.get_json(cache=False)
                if not req_data:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if "k_adi" not in req_data or "k_sifre" not in req_data:
                    raise ReqDataErrors.req_data_incomplete()
                if req_data["k_adi"] is None or req_data["k_sifre"] is None:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if req_data["k_adi"] == "" or req_data["k_sifre"] == "":
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
                db_op_result = add_user(Kullanici(k_adi=req_data["k_adi"], k_sifre_hash=req_data["k_sifre"]))
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
        return jsonify({"status": "error", "message": "unauthorized"}), 401
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
    return not_found()


@main_blueprint.route("/giris", methods=["GET", "POST"])
def giris() -> tuple[Response, int]:
    if request.method == "POST":
        if (is_user := get_user_from_req(request)) is not None and is_user is not False:
            match try_login(is_user, ip_addr=request.remote_addr):
                case girisHata.sifre_veya_kullanici_adi_yanlis:
                    return (
                        jsonify({"status": "error", "message": "wrong_password_or_username"}),
                        200,
                    )
                case girisHata.maksimum_online_kullanici:
                    return (
                        jsonify({"status": "error", "message": "maximum_online_user_quota"}),
                        200,
                    )
                case girisHata.kullanici_bulunamadi:
                    return (
                        jsonify({"status": "error", "message": "user_not_found"}),
                        200,
                    )
                case girisHata.paket_bulunamadi:
                    return (
                        jsonify({"status": "error", "message": "packet_not_found"}),
                        200,
                    )
                case girisHata.paket_suresi_bitti:
                    return (
                        jsonify({"status": "error", "message": "packet_time_expired"}),
                        200,
                    )
                case True:
                    return (
                        jsonify({"status": "succes", "message": "user_logged_in"}),
                        200,
                    )
            return jsonify({"status": "error", "message": "login_failed"}), 200
        return jsonify({"status": "error", "message": "user_not_found"}), 200
    return not_found()


def get_user_from_req(request) -> bool | Kullanici | None:
    if request.headers.get("Authorization") is None:
        return None
    else:
        user = Kullanici.query.filter_by(k_adi=request.authorization.username).first()
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