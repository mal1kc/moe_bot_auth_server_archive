import click
import logging
from flask import Blueprint, Response, jsonify, request
from schema import And, Schema, SchemaError, SchemaWrongKeyError
import sqlalchemy


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
    get_user,
    loginError,
    pContentEnum,
    try_login,
    update_package,
    update_package_content,
    update_u_package,
    update_u_session,
    update_user,
)

from .crpytion import compare_encypted_hashes, unmake_password_ready, make_password_hash

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
    if (
        db_op_result := add_admin(Admin(name="mal1kc", password_hash=make_password_hash("deov04ın-!ıj0dı12klsa")))
    ) != DBOperationResult.success:
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
            package_contents=[
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
                package_contents=[
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


@main_blueprint.route(endpoints.URLS.ARegister, methods=["GET", "POST"])
def admin_register() -> tuple[Response, int]:
    """
    model register endpoint for admins
    """
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "POST":
        is_admin = get_admin_from_req(request=request)
        LOGGER.debug(f"{req_id} - admin : {is_admin}")
        if is_admin:
            try:
                req_data = request.get_json(cache=False)
                if not req_data:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if "model_type" not in req_data or "model" not in req_data:
                    raise ReqDataErrors.req_data_incomplete()
                if req_data["model_type"] is None or req_data["model"] is None:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                json_schema = Schema(
                    {
                        "model_type": str,
                        "model": dict,
                    }
                )

                json_schema.validate(req_data)
                if req_data["model_type"] == "" or req_data["model"] == "":
                    raise ReqDataErrors.req_data_is_none_or_empty()
                elif req_data["model_type"] == "user":
                    LOGGER.debug(f"{req_id} - trying to add user")
                    user = User.from_json(data=req_data["model"])
                    if get_user(user.name) is not None:
                        return request_error_response("user_already_exists"), 400
                    db_op_result = add_user(User(name=user.name, password_hash=unmake_password_ready(user.password_hash)))
                    if db_op_result is DBOperationResult.success:
                        db_user = User.query.filter_by(name=user.name).first()
                        return (
                            request_success_response(success_msg="user_created", extra={"user": db_user.__json__()}),
                            200,
                        )
                    return request_error_response("db_error", extra=db_op_result.__json__()), 400
                elif req_data["model_type"] == "package":
                    LOGGER.debug(f"{req_id} - trying to add package")
                    package = Package.from_json(req_data["model"])
                    if hasattr(req_data["model"], "packagecontents"):
                        if req_data["model"]["packagecontents"] is not None:
                            for package_content in req_data["model"]["packagecontents"]:
                                if isinstance(package_content, str):
                                    try:
                                        package_content = PackageContent.query.filter_by(name=package_content).first()
                                    except Exception as e:
                                        LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                                        LOGGER.debug(f"{req_id} - error ignored, continuing... add package")
                                        break
                                if isinstance(package_content, int):
                                    db_package_content = PackageContent.query.filter_by(id=package_content).first()
                                    if isinstance(db_package_content, PackageContent):
                                        package.packagecontents.append(package_content)
                                    else:
                                        LOGGER.debug(f"{req_id} - package_content not found")
                                        return (
                                            request_error_response(
                                                "package_content_not_found", extra={"packet_content": {"id": package_content}}
                                            ),
                                            404,
                                        )
                                elif isinstance(package_content, dict):
                                    LOGGER.debug(f"{req_id} - package_content is dict, trying to add")
                                    package_content = PackageContent.from_json(package_content)
                                    if add_package_content(package_content) != DBOperationResult.success:
                                        LOGGER.debug(f"{req_id} - package_content not added")
                                        return (
                                            request_error_response(
                                                "package_content_not_added", extra={"package_content": package_content.__json__()}
                                            ),
                                            400,
                                        )
                                    db_package_content = PackageContent.query.filter_by(name=package_content.name).first()
                                    package.packagecontents.append(db_package_content)

                                # if PackageContent.query.filter_by(name=package_content).first() is None:
                                #     return request_error_response("package_content_not_found"), 404

                    db_op_result = add_package(package)
                    if db_op_result is DBOperationResult.success:
                        db_package = Package.query.filter_by(name=package.name).first()
                        return (
                            request_success_response(success_msg="package_created", extra={"package": db_package.__json__()}),
                            200,
                        )
                    return request_error_response("db_error", extra=db_op_result.__json__()), 400
                elif req_data["model_type"] == "package_content":
                    LOGGER.debug(f"{req_id} - trying to add package_content")
                    package_content = PackageContent.from_json(req_data["model"])
                    db_op_result = add_package_content(package_content)
                    if db_op_result is DBOperationResult.success:
                        return (
                            request_success_response(
                                success_msg="package_content_created",
                                extra={"package_content": package_content.__json__()},
                            ),
                            200,
                        )
                    return request_error_response("db_error", extra=db_op_result.__json__()), 400
                elif req_data["model_type"] == "u_package":
                    LOGGER.debug(f"{req_id} - trying to add u_package")

                    u_package = U_Package.from_json(req_data["model"])
                    db_op_result = add_u_package(u_package)
                    if db_op_result is DBOperationResult.success:
                        return (
                            request_success_response(
                                success_msg="u_package_created", extra={"u_package": u_package.__json__(user_incld=False)}
                            ),
                            200,
                        )
                    LOGGER.debug(f"{req_id} - db_op_result : {db_op_result}")
                    return request_error_response("db_error", extra=db_op_result.__json__()), 400
                return (
                    request_error_response(
                        "unsupported_model_type",
                        extra={"detail": {"supported_model_types": ["user", "package", "package_content", "u_package"]}},
                    ),
                    400,
                )
            except SchemaError as schErr:
                LOGGER.debug(f"{req_id} - catched schema error : {schErr}")
                if schErr.code.startswith("Missing key"):
                    if schErr.code[11] == "s":
                        return req_data_is_none_or_empty()
                    return req_data_incomplete()
                if schErr.code.startswith("Key"):
                    return req_data_is_none_or_empty()
                if SchemaError is SchemaWrongKeyError:
                    return req_data_incomplete()
                return bad_request(schErr)
            except AttributeError as e:
                LOGGER.debug(f"{req_id} - catched attribute error : {e}")
                if str(e).endswith("object has no attribute 'get'"):
                    return unsupported_media_type()
                return bad_request(e)
            except ReqDataErrors.req_data_incomplete:
                LOGGER.debug(f"{req_id} - catched req_data_incomplete error")
                return req_data_incomplete()
            except ReqDataErrors.req_data_is_none_or_empty:
                LOGGER.debug(f"{req_id} - catched req_data_is_none_or_empty error")
                return req_data_is_none_or_empty()
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


@main_blueprint.route(endpoints.URLS.AUpdate, methods=["PUT"])
def admin_update() -> tuple[Response, int]:  # TODO: refactor this
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    # can method be changed to PUT?
    if request.method == "PUT":
        is_admin = get_admin_from_req(request=request)
        LOGGER.debug(f"{req_id} - admin : {is_admin}")
        if is_admin:
            try:
                req_data = request.get_json(cache=False)
                if not req_data:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if "model_type" not in req_data or "model" not in req_data:
                    raise ReqDataErrors.req_data_incomplete()
                if req_data["model_type"] is None or req_data["model"] is None:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                json_schema = Schema(
                    {
                        "model_type": str,
                        "model": And(dict, lambda x: "id" in x, error="model_id_not_found"),
                    }
                )

                json_schema.validate(req_data)
                if req_data["model_type"] == "" or req_data["model"] == "":
                    raise ReqDataErrors.req_data_is_none_or_empty()
                elif req_data["model_type"] == "user":
                    LOGGER.debug(f"{req_id} - trying to update user")
                    req_user = User.from_json(data=req_data["model"])
                    db_user = User.query.filter_by(id=req_user.id).first()
                    if db_user is None:
                        return request_error_response("user_not_found"), 404
                    if update_user(db_user, req_user) == DBOperationResult.success:
                        return (
                            request_success_response(success_msg="user_updated", extra={"user": db_user.__json__()}),
                            200,
                        )
                    return request_error_response("db_error"), 400
                elif req_data["model_type"] == "package":
                    LOGGER.debug(f"{req_id} - trying to update package")
                    req_package = Package.from_json(req_data["model"])
                    db_package = Package.query.filter_by(id=req_package.id).first()
                    if hasattr(req_data["model"], "package_contents"):
                        for rqpackage_content in req_package["package_contents"]:
                            if isinstance(rqpackage_content, str):
                                db_package.packagecontents.append(PackageContent.query.filter_by(name=rqpackage_content).first())
                            elif isinstance(rqpackage_content, int):
                                db_package.packagecontents.append(PackageContent.query.filter_by(id=rqpackage_content).first())
                            elif isinstance(rqpackage_content, dict):
                                rqpackage_content = PackageContent.from_json(rqpackage_content)
                                if add_package_content(rqpackage_content) != DBOperationResult.success:
                                    return (
                                        request_error_response(
                                            "package_content_not_added", extra={"package_content": rqpackage_content.__json__()}
                                        ),
                                        400,
                                    )
                                db_package.packagecontents.append(PackageContent.query.filter_by(name=rqpackage_content.name).first())
                    if db_package is None:
                        return request_error_response("package_not_found"), 404
                    if update_package(db_package, req_package) == DBOperationResult.success:
                        return (
                            request_success_response(success_msg="package_updated", extra={"package": db_package.__json__()}),
                            200,
                        )
                    return request_error_response("db_error"), 400
                elif req_data["model_type"] == "package_content":
                    LOGGER.debug(f"{req_id} - trying to update package_content")
                    req_package_content = PackageContent.from_json(req_data["model"])
                    db_package_content = PackageContent.query.filter_by(id=req_package_content.id).first()
                    if db_package_content is None:
                        return request_error_response("package_content_not_found"), 404
                    if update_package_content(db_package_content, req_package_content) == DBOperationResult.success:
                        return (
                            request_success_response(
                                success_msg="package_content_updated",
                                extra={"package_content": db_package_content.__json__()},
                            ),
                            200,
                        )
                    return request_error_response("db_error"), 400
                elif req_data["model_type"] == "u_package":
                    LOGGER.debug(f"{req_id} - trying to update u_package")

                    LOGGER.critical("eror loc 1")
                    req_u_package = U_Package.from_json(req_data["model"])
                    LOGGER.critical("eror loc 2")
                    db_u_package = U_Package.query.filter_by(id=req_u_package.id).first()
                    LOGGER.critical("eror loc 3")
                    if db_u_package is None:
                        return request_error_response("u_package_not_found"), 404
                    if update_u_package(db_u_package, req_u_package) == DBOperationResult.success:
                        return (
                            request_success_response(
                                success_msg="u_package_updated", extra={"u_package": db_u_package.__json__(user_incld=False)}
                            ),
                            200,
                        )
                    return request_error_response("db_error"), 400
                elif req_data["model_type"] == "u_session":
                    LOGGER.debug(f"{req_id} - trying to update u_session")
                    req_u_session = U_Package.from_json(req_data["model"])
                    db_u_session = U_Package.query.filter_by(id=req_u_session.id).first()
                    if db_u_session is None:
                        return request_error_response("u_session_not_found"), 404
                    if update_u_session(db_u_session, req_u_session) == DBOperationResult.success:
                        return (
                            request_success_response(
                                success_msg="u_session_updated", extra={"u_session": db_u_session.__json__(user_incld=False)}
                            ),
                            200,
                        )
                    return request_error_response("db_error"), 400
                return (
                    request_error_response(
                        "unsupported_model_type",
                        extra={"detail": {"supported_model_types": ["user", "package", "package_content", "u_package"]}},
                    ),
                    400,
                )
            except SchemaError as schErr:
                if schErr.code.startswith("Missing key"):
                    if schErr.code[11] == "s":
                        return req_data_is_none_or_empty()
                    return req_data_incomplete()
                if schErr.code.startswith("Key"):
                    return req_data_is_none_or_empty()
                if SchemaError is SchemaWrongKeyError:
                    return req_data_incomplete()
                return bad_request(schErr)
            except AttributeError as e:
                if str(e).endswith("object has no attribute 'get'"):
                    return unsupported_media_type()
                return bad_request(e)
            except ReqDataErrors.req_data_incomplete:
                return req_data_incomplete()
            except ReqDataErrors.req_data_is_none_or_empty:
                return req_data_is_none_or_empty()
            except sqlalchemy.exc.IntegrityError as e:
                if "Duplicate entry" in str(e):
                    return request_error_response("duplicate_entry"), 400
                if "foreign key constraint fails" in str(e):
                    return request_error_response("foreign_key_constraint_fails"), 400
                if "NOT NULL constraint failed" in str(e):
                    return request_error_response("not_null_constraint_failed"), 400
                return bad_request(e)
            except Exception as e:
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


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
                        request_success_response("login_success", extra={"user": is_user.__json__()}),
                        200,
                    )
            return jsonify({"status": "error", "message": "login_failed"}), 200
        return jsonify({"status": "error", "message": "user_cred_not_found"}), 404
    return unauthorized()


def get_user_from_req(request) -> bool | User | None:
    if request.headers.get("Authorization") is None:
        return None
    user = User.query.filter_by(name=request.authorization.username).first()
    if user is None:
        return None
    if compare_encypted_hashes(request.authorization.password, user.password_hash):
        return user
    return False


def get_admin_from_req(request) -> bool | None:
    if request.headers.get("Authorization") is None:
        return None
    admin = Admin.query.filter_by(name=request.authorization.username).first()
    if admin is None:
        return False
    if compare_encypted_hashes(
        request.authorization.password,
        admin.password_hash,
    ):
        return True
    return False


def generate_req_id(remote_addr: str | None) -> str:
    from uuid import uuid4

    return str(remote_addr) + "_" + str(uuid4())
