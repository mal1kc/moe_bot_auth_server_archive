import click
import logging
from flask import Blueprint, Response, jsonify, request
from schema import And, Schema, SchemaError

from .err_handlrs import (
    bad_request,
    method_not_allowed,
    unauthorized,
    unsupported_media_type,
    req_data_incomplete,
    req_data_is_none_or_empty,
)

from .base_responses import request_error_response, request_success_response
from .database_ops import (
    Admin,
    DBOperationResult,
    Package,
    PackageContent,
    U_Package,
    User,
    add_admin,
    add_package,
    add_u_package,
    add_package_content,
    add_user,
    db,
    loginError,
    pContentEnum,
    try_login,
)

from .crpytion import simple_dencrypt, sha256

from werkzeug.exceptions import UnsupportedMediaType
from .config import endpoints

main_blueprint = Blueprint("page", __name__, cli_group=None)


class ReqDataErrors(Exception):
    class req_data_is_none_or_empty(Exception):
        pass

    class req_data_incomplete(Exception):
        pass


LOGGER = logging.getLogger(__name__)


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
    if (db_op_result := add_admin(Admin(name="mal1kc", password_hash=sha256("deov04ın-!ıj0dı12klsa")))) != DBOperationResult.success:
        print(" ❌ admin eklenemedi ❌ ")
        print(" ❌ veritabanı oluşturulamadı ❌ ")
        print(" ❌ Hata: %s ❌ ", db_op_result)
        return
    print(" ☑ admin eklendi")
    db.session.commit()

    print("temel package icerikler ekleniyor")
    for package_content_deger in pContentEnum:
        p_icerik = PackageContent(
            name=package_content_deger,
            content_value=pContentEnum[package_content_deger],
        )
        add_package_content(p_icerik)
    print(" ☑ temel package icerikler eklendi")
    print("temel packageler ekleniyor")
    db_op_result = add_package(
        Package(
            name="moe_gatherer",
            packagecontents=[
                PackageContent.query.filter_by(name=pContentEnum.moe_gatherer).first(),
            ],
            days=60,
        )
    )
    if db_op_result != DBOperationResult.success:
        print(" ❌ package eklenemedi ❌ ")
        print(" ❌ veritabanı oluşturulamadı ❌ ")
        print(" ❌ Hata: %s ❌ ", db_op_result)
        return

    if (
        db_op_result := add_package(
            Package(
                name="moe_gatherer+eksra_user",
                packagecontents=[
                    PackageContent.query.filter_by(name=pContentEnum.moe_gatherer).first(),
                    PackageContent.query.filter_by(name=pContentEnum.extra_user).first(),
                ],
                days=60,
            ),
        )
        != DBOperationResult.success
    ):
        print(" ❌ package eklenemedi ❌ ")
        print(" ❌ veritabanı oluşturulamadı ❌ ")
        print(" ❌ Hata: %s ❌ ", db_op_result)
        return

    print(" ☑ temel package eklendi")
    db.session.commit()
    db_packageler = [package.__json__() for package in Package.query.all()]
    db_package_contentleri = [package_content.__json__() for package_content in PackageContent.query.all()]
    db_kullanicilar = [kullanici.__json__() for kullanici in User.query.all()]
    db_adminler = [admin.__json__() for admin in Admin.query.all()]
    print("veritabanı oluşturuldu")
    print("veritabanı içeriği : ")
    print("packageler ->")
    pprint(db_packageler)
    print("package İçerikleri ->")
    pprint(db_package_contentleri)
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


# TODO: add update package and package content, update user package
# TODO: seperate admin endpoints to methods


@main_blueprint.route(endpoints.URLS.APRegister, methods=["GET", "POST"])
def admin_package_register() -> tuple[Response, int]:
    """
    package and package content register endpoint for admins
    """
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "POST":
        _is_admin = is_admin(request=request)
        LOGGER.debug(f"{req_id} - admin : {_is_admin}")
        if _is_admin:
            try:
                req_data = request.get_json(cache=False)
                if not req_data:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if "m_type" not in req_data or "model" not in req_data:
                    raise ReqDataErrors.req_data_incomplete()
                if req_data["m_type"] is None or req_data["model"] is None:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                json_schema = Schema(
                    {
                        "m_type": str,
                        "model": dict,
                    }
                )

                json_schema.validate(req_data)
                if req_data["m_type"] == "" or req_data["model"] == "":
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if req_data["m_type"] == "package":
                    try:
                        model = Package.from_json(req_data["model"])
                        add_package(model)
                    except Exception as SchemaError:
                        return bad_request(SchemaError)
                    return request_success_response("package_created"), 200
                elif req_data["m_type"] == "package_content":
                    model = PackageContent.from_json(req_data["model"])
                    add_package_content(model)
                    return request_success_response("package_content_created"), 200
                elif req_data["m_type"] == "user_package":
                    model = U_Package.from_json(req_data["model"])
                    add_u_package(model)
                    return request_success_response("user_package_created"), 200
                return bad_request("invalid_model_type")
            except ReqDataErrors.req_data_incomplete:
                return req_data_incomplete()
            except ReqDataErrors.req_data_is_none_or_empty:
                return req_data_is_none_or_empty()
            except Exception as e:
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    elif request.method == "GET":
        _is_admin = is_admin(request=request)
        LOGGER.debug(f"{req_id} - admin : {_is_admin}")
        if _is_admin:
            all_packages = [package.__json__() for package in Package.query.all()]
            all_packagecontents = [package_content.__json__() for package_content in PackageContent.query.all()]
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "db_content",
                        "packages": all_packages,
                        "package_contents": all_packagecontents,
                    }
                ),
                200,
            )
        return unauthorized()
    else:
        return method_not_allowed()


@main_blueprint.route(endpoints.URLS.URegister, methods=["GET", "POST"])
def user_register() -> tuple[Response, int]:
    """
    user register endpoint for admins
    """
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "POST":
        _is_admin = is_admin(request=request)
        LOGGER.debug(f"{req_id} - admin : {_is_admin}")
        if _is_admin:
            try:
                LOGGER.debug(f"{req_id} - trying to get json data")
                req_data = request.get_json(cache=False)
                LOGGER.debug(f"{req_id} - req_data : {req_data}")
                json_schema = Schema({"name": And(str, len), "password_hash": And(str, len)})
                json_schema.validate(req_data)
            except SchemaError as schErr:
                LOGGER.debug(f"{req_id} - catched schema error : {schErr}")
                # TODO : i dont like this
                #  - future add enum for error codes or rewrite schema lib (prob. second)
                if schErr.code.startswith("Missing key"):
                    if schErr.code[11] == "s":  # 11 is len("Missing key")
                        return req_data_is_none_or_empty()
                    return req_data_incomplete()
                if schErr.code.startswith("Key"):
                    return req_data_is_none_or_empty()
                return bad_request(schErr)
            except AttributeError as e:
                LOGGER.debug(f"{req_id} - catched attribute error : {e}")
                return bad_request(e)
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
            else:
                LOGGER.debug(f"{req_id} - trying to add user")
                db_op_result = add_user(
                    User(name=req_data["name"], password_hash=simple_dencrypt(req_data["password_hash"]).decode("utf-8"))
                )
                LOGGER.debug(f"{req_id} - db_op_result : {db_op_result}")
                match db_op_result:
                    case DBOperationResult.model_already_exists:
                        return request_error_response("user_already_exists"), 400
                    case DBOperationResult.unknown_error:
                        return request_error_response("unknown_error"), 400
                    case DBOperationResult.model_name_too_short:
                        return request_error_response("user_name_too_short"), 400
                    case DBOperationResult.model_name_too_long:
                        return request_error_response("user_name_too_long"), 400
                    case DBOperationResult.model_passhash_too_short:
                        return request_error_response("user_passhash_too_short"), 400
                    case DBOperationResult.success:
                        return request_success_response("user_created"), 200
                    case _:
                        return request_error_response("unknown_error"), 400
        LOGGER.debug(f"{req_id} - admin is None or False")
        return unauthorized()
    elif request.method == "GET":
        _is_admin = is_admin(request=request)
        LOGGER.debug(f"{req_id} - admin : {_is_admin}")
        if _is_admin:
            all_users = [kullanici.__json__() for kullanici in User.query.all()]
            all_packages = [package.__json__() for package in Package.query.all()]
            all_packagecontents = [package_content.__json__() for package_content in PackageContent.query.all()]
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "db_content",
                        "users": all_users,
                        "packages": all_packages,
                        "package_contents": all_packagecontents,
                    }
                ),
                200,
            )
        return unauthorized()
    return bad_request()


@main_blueprint.route(endpoints.URLS.ULogin, methods=["GET", "POST"])
def user_login() -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "POST":
        is_user = get_user_from_req(request)
        LOGGER.debug(f"{req_id} - is_user : {is_user}")
        if isinstance(is_user, User):
            LOGGER.debug(f"{req_id} - trying to login")
            if (try_login_response := try_login(is_user, ip_addr=request.remote_addr)) is not None:
                LOGGER.debug(f"{req_id} - login result : {try_login_response}")
                if try_login_response is loginError.max_online_user:
                    return (
                        request_error_response("max_online_user"),
                        401,
                    )
                elif try_login_response is loginError.user_not_found:
                    return (
                        request_error_response("user_not_found"),
                        404,
                    )
                elif try_login_response is loginError.user_not_have_package:
                    return (
                        request_error_response("package_not_found"),
                        404,
                    )
                elif try_login_response is loginError.user_package_expired:
                    return (
                        request_error_response("package_expired"),
                        410,
                    )
                elif try_login_response is True:
                    return (
                        request_success_response("login_success"),
                        200,
                    )
            return jsonify({"status": "error", "message": "login_failed"}), 200
        return jsonify({"status": "error", "message": "user_cred_not_found"}), 404
    return unauthorized()


@main_blueprint.route(endpoints.URLS.UPInfo, methods=["GET"])
def user_package_info() -> tuple[Response, int]:
    """
    user package info endpoint for users
    """
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "GET":
        is_user = get_user_from_req(request)
        LOGGER.debug(f"{req_id} - is_user : {is_user}")
        if isinstance(is_user, User):
            LOGGER.debug(f"{req_id} - trying to get package info")
            upackage = is_user.package
            LOGGER.debug(f"{req_id} - upackage : {upackage}")
            if upackage is None:
                return (
                    request_error_response("user_not_have_package"),
                    404,
                )  # hope this never happens
            if upackage.is_expired():
                return (
                    request_error_response("package_expired"),
                    410,
                )
            return (
                jsonify({"status": "success", "message": "package_info", "package": upackage.__json__(user_incld=False)}),
                200,
            )
        if isinstance(is_user, bool):
            return request_error_response("login_failed"), 400
        return request_error_response("user_cred_not_found"), 404
    return method_not_allowed()


def get_user_from_req(request) -> bool | User | None:
    if request.headers.get("Authorization") is None:
        return None
    user = User.query.filter_by(name=request.authorization.username).first()
    if user is None:
        return None
    if simple_dencrypt(request.authorization.password).decode("utf-8") != user.password_hash:
        return False
    return user


def is_admin(request) -> bool | None:
    if request.headers.get("Authorization") is None:
        return None
    admin = Admin.query.filter_by(name=request.authorization.username).first()
    if admin is None:
        return False
    # if request.authorization.password == admin.password_hash:
    #     return False
    if simple_dencrypt(request.authorization.password).decode("utf-8") != admin.password_hash:
        return False
    return True


def generate_req_id(remote_addr: str | None) -> str:
    from uuid import uuid4

    return str(remote_addr) + "_" + str(uuid4())
