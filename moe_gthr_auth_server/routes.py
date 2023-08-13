from typing import Literal

from flask import Blueprint, Flask, Response, abort, json, jsonify, request

from .database_ops import Admin, Kullanici, Paket, PaketIcerik, add_user, db, girisHata, sha256_hash, try_login

main_blueprint = Blueprint("page", __name__)


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
def kayit(model: Kullanici | None = None) -> tuple[Response, int]:
    if request.method == "POST":
        if admin := is_admin(request=request):
            if admin == "bad_request":
                return jsonify({"status": "error", "message": "bad_request"}), 400
            if model is None:
                return jsonify({"status": "error", "message": "model is None"}), 200
            add_user(model)
            return jsonify({"status": "ok"}), 200
    else:
        if admin := is_admin(request=request):
            if admin == "bad_request":
                return jsonify({"status": "error", "message": "bad_request"}), 400
            all_users = Kullanici.query.all()
            all_packets = Paket.query.all()
            all_packet_contents = PaketIcerik.query.all()
            return jsonify({"status": "ok", "users": all_users, "packets": all_packets, "packet_contents": all_packet_contents}), 200
    return not_found()


@main_blueprint.route("/giris", methods=["GET", "POST"])
def giris() -> tuple[Response, int]:
    if request.method == "POST":
        if (is_user := get_user_from_req(request)) is not None:
            match try_login(is_user):
                case girisHata.sifre_veya_kullanici_adi_yanlis:
                    return jsonify({"status": "error", "message": "wrong_password_or_username"}), 200
                case girisHata.maksimum_online_kullanici:
                    return jsonify({"status": "error", "message": "maximum_online_user_quota"}), 200
                case girisHata.kullanici_bulunamadi:
                    return jsonify({"status": "error", "message": "user_not_found"}), 200
                case girisHata.paket_bulunamadi:
                    return jsonify({"status": "error", "message": "packet_not_found"}), 200
                case girisHata.paket_suresi_bitti:
                    return jsonify({"status": "error", "message": "packet_time_expired"}), 200
                case True:
                    return jsonify({"status": "succes", "message": "user_logged_in"}), 200
            return jsonify({"status": "error", "message": "login_failed"}), 200
        return jsonify({"status": "error", "message": "user_not_found"}), 200
    return not_found()


@main_blueprint.errorhandler(404)
def not_found(error=None) -> tuple[Response, int]:
    return jsonify({"status": "not_found"}), 404


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


# def is_admin_decorator(f):
#     def wrpageer(*args, **kwargs):
#         if request.headers.get("Authorization") is None:
#             return jsonify({"status": "not_authorized"}), 401
#         else:
#             admin = Admin.query.filter_by(a_adi=request.authorization.username).first()
#             if admin is None:
#                 return not_found()
#             if request.authorization.password != admin.a_sifre_hash:
#                 return not_found()
#             else:
#                 return f(*args, **kwargs)

#     wrpageer.__name__ = f.__name__
#     return wrpageer
