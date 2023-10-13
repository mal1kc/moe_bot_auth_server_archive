import logging

import sqlalchemy
from flask import Blueprint, Response, jsonify, request, session
from schema import And, Schema, SchemaError, SchemaWrongKeyError, Use
from sqlalchemy.orm import scoped_session
from werkzeug.exceptions import UnsupportedMediaType

from moe_bot_auth_server.database_ops import (
    Admin,
    DBOperationResult,
    Package,
    PackageContent,
    U_Package,
    U_Session,
    User,
    add_package,
    add_package_content,
    add_u_package,
    add_user,
    db,
    delete_model,
    get_package_by_id,
    get_package_content_by_id,
    get_u_package_by_id,
    get_u_session_by_id,
    get_user,
    get_user_by_id,
    loginError,
    try_login,
    update_package,
    update_package_content,
    update_u_package,
    update_u_session,
    update_user,
)
from moe_bot_auth_server.enums import mType

from .base_responses import (
    req_data_incomplete,
    req_data_is_none_or_empty,
    request_error_response,
    request_success_response,
)
from .config import endpoints
from .cryption import compare_encypted_hashes, unmake_password_ready
from .err_handlrs import (
    bad_request,
    method_not_allowed,
    unauthorized,
    unsupported_media_type,
)

main_blueprint = Blueprint("page", __name__, cli_group=None)


class ReqDataErrors(Exception):
    class req_data_is_none_or_empty(Exception):
        pass

    class req_data_incomplete(Exception):
        pass


LOGGER = logging.getLogger("main_app")


@main_blueprint.route("/", methods=["GET", "POST"])
def anasayfa():
    return jsonify({"status": "OK"})


@main_blueprint.route(endpoints.URLS.ARegister, methods=["POST"])
def admin_register(m_type: mType) -> tuple[Response, int]:
    """
    model register endpoint for admins
    """
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "POST":
        try:
            is_admin = get_admin_from_req(request=request)
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            if is_admin:
                req_data = request.get_json(cache=False)
                if not req_data:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                    # if "model_type" not in req_data or "model" not in req_data:
                if req_data["model"] is None:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                json_schema = Schema(
                    {
                        "model": dict,
                    }
                )

                json_schema.validate(req_data)
                if m_type == mType.user:
                    LOGGER.debug(f"{req_id} - trying to add user")
                    return admin_register_user(req_data["model"])
                elif m_type == mType.package:
                    LOGGER.debug(f"{req_id} - trying to add package")
                    return admin_register_package(req_data["model"])
                elif m_type == mType.package_content:
                    LOGGER.debug(f"{req_id} - trying to add package_content")
                    return admin_register_package_content(req_data["model"])
                elif m_type == mType.u_package:
                    LOGGER.debug(f"{req_id} - trying to add u_package")
                    return admin_register_u_package(req_data["model"])
                elif m_type == mType.u_session:
                    LOGGER.debug(f"{req_id} - trying to add u_session")
                    return admin_register_u_session(req_data["model"])
                return (
                    request_error_response(
                        "unsupported_model_type",
                        extra={
                            "detail": {
                                "supported_model_types": [
                                    "user",
                                    "package",
                                    "package_content",
                                    "u_package",
                                ]
                            }
                        },
                    ),
                    400,
                )
        except SchemaError as schErr:
            # TODO: improve error messages
            LOGGER.debug(f"{req_id} - catched schema error : {schErr}")
            if schErr.code.startswith("invalid"):
                return (
                    request_error_response("invalid_data", extra={"detail": schErr.code}),
                    400,
                )
            if schErr.code == "not_valid_data":
                return (
                    request_error_response("invalid_data", extra={"detail": schErr.code}),
                    400,
                )
            elif schErr.code.startswith("Missing keys"):
                return req_data_incomplete(extra={"detail": schErr.code})
            elif schErr.code.startswith("Missing key"):
                return req_data_incomplete()
            elif schErr.code.startswith("Key"):
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


def admin_register_user(user_data: dict[str, str | int]) -> tuple[Response, int]:
    """
    register user with given data
    """
    user = User.from_json(data=user_data)
    if get_user(user.name) is not None:
        return request_error_response("user_already_exists"), 400
    db_op_result = add_user(
        User(
            name=user.name,
            password_hash=unmake_password_ready(user.password_hash),
        )
    )
    if db_op_result is DBOperationResult.success:
        db_user = User.query.filter_by(name=user.name).first()
        return (
            request_success_response(
                success_msg="user_created",
                extra={"user": db_user.__json__()},
            ),
            200,
        )
    return (
        request_error_response("db_error", extra=db_op_result.__json__()),
        400,
    )


def admin_register_package(
    package_data: dict[str, str | int | list[int | PackageContent]]
) -> tuple[Response, int]:
    """
    register package with given data
    """
    req_package_data = Package.from_json(package_data)
    db_op_result = add_package(req_package_data)
    if db_op_result is DBOperationResult.success:
        db_package = Package.query.filter_by(name=req_package_data.name).first()
        return (
            request_success_response(
                success_msg="package_created",
                extra={"package": db_package.__json__()},
            ),
            200,
        )
    return (
        request_error_response("db_error", extra=db_op_result.__json__()),
        400,
    )


def admin_register_package_content(
    package_content_data: dict[str, str | int]
) -> tuple[Response, int]:
    """
    register package_content with given data
    """
    req_package_content_data = PackageContent.from_json(package_content_data)
    db_op_result = add_package_content(req_package_content_data)
    if db_op_result is DBOperationResult.success:
        db_package_content = PackageContent.query.filter_by(
            name=req_package_content_data.name
        ).first()
        return (
            request_success_response(
                success_msg="package_content_created",
                extra={"package_content": db_package_content.__json__()},
            ),
            200,
        )
    return (
        request_error_response("db_error", extra=db_op_result.__json__()),
        400,
    )


def admin_register_u_package(u_package_data: dict[str, str | int]) -> tuple[Response, int]:
    """
    register u_package with given data
    """
    req_u_package_data = U_Package.from_json(u_package_data)
    db_op_result = add_u_package(req_u_package_data)
    # TODO: also add base_package of u_package to db with package_contents
    if db_op_result is DBOperationResult.success:
        db_u_package = U_Package.query.filter_by(user_id=req_u_package_data.user_id).first()
        return (
            request_success_response(
                success_msg="u_package_created",
                extra={"u_package": db_u_package.__json__()},
            ),
            200,
        )
    return (
        request_error_response("db_error", extra=db_op_result.__json__()),
        400,
    )


def admin_register_u_session(u_session_data: dict[str, str | int]) -> tuple[Response, int]:
    """
    register u_session with given data
    IMPORTANT : currently not implemented , \
        because u_session should be only created by user login
    """
    _ = u_session_data
    return method_not_allowed()


@main_blueprint.route(endpoints.URLS.AUpdate, methods=["PUT"])
def admin_update(m_type: int, m_id: int) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    # can method be changed to PUT?
    if request.method == "PUT":
        try:
            is_admin = get_admin_from_req(request=request)
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            if is_admin:
                req_data = request.get_json(cache=False)
                if not req_data:
                    raise ReqDataErrors.req_data_is_none_or_empty()
                if "new_model" not in req_data:
                    raise ReqDataErrors.req_data_incomplete()
                required_atleast_keys = [
                    "name",
                    "password_hash",
                    "days",
                    "detail",
                    "content_value",
                    "start_date",
                ]
                json_schema = Schema(
                    {
                        "new_model": And(
                            dict,
                            Use(
                                lambda x_dict: (
                                    key in required_atleast_keys for key in x_dict.keys()
                                ),
                                error="unsupported_key",
                            ),
                        ),
                    }
                )

                json_schema.validate(req_data)
                if m_type == mType.all_models:
                    return (
                        request_error_response(
                            "unsupported_model_type",
                        ),
                        400,
                    )
                elif m_type == mType.user:
                    return admin_update_user(m_id, req_data["new_model"], db.session)
                elif m_type == mType.package:
                    return admin_update_package(m_id, req_data["new_model"])
                elif m_type == mType.package_content:
                    return admin_update_package_content(m_id, req_data["new_model"])
                elif m_type == mType.u_package:
                    return admin_update_u_package(m_id, req_data["new_model"])
                elif m_type == mType.u_session:
                    return admin_update_u_session(m_id, req_data["new_model"])
                return (
                    request_error_response(
                        "unsupported_model_type",
                        extra={
                            "detail": {
                                "supported_model_types": [
                                    "user",
                                    "package",
                                    "package_content",
                                    "u_package",
                                ],
                                "enum_values": [
                                    mType.user,
                                    mType.package,
                                    mType.package_content,
                                    mType.u_package,
                                ],
                            }
                        },
                    ),
                    400,
                )
        except SchemaError as schErr:
            # TODO: improve error messages
            LOGGER.debug(f"{req_id} - catched schema error : {schErr}")
            if schErr.code.startswith("Missing key"):
                if schErr.code[11] == "s":
                    return req_data_is_none_or_empty()
                return req_data_incomplete()
            if schErr.code.startswith("Key"):
                return req_data_is_none_or_empty()
            if SchemaError is SchemaWrongKeyError:
                return req_data_incomplete()
            if "new_model_id_not_found" in schErr.code:
                return request_error_response("new_model_id_not_found"), 400
            return bad_request(schErr)
        except AttributeError as e:
            if str(e).endswith("object has no attribute 'get'"):
                return unsupported_media_type()
            return bad_request(e)
        except ReqDataErrors.req_data_incomplete:
            return req_data_incomplete()
        except ReqDataErrors.req_data_is_none_or_empty:
            return req_data_is_none_or_empty()
        except sqlalchemy.exc.IntegrityError as e:  # type: ignore
            if "Duplicate entry" in str(e):
                return request_error_response("duplicate_entry"), 400
            if "foreign key constraint fails" in str(e):
                return request_error_response("foreign_key_constraint_fails"), 400
            if "NOT NULL constraint failed" in str(e):
                return (
                    request_error_response(
                        "not_null_constraint_failed",
                        extra={
                            "db_error": str(e),
                        },
                    ),
                    400,
                )
            return bad_request(e)
        except Exception as e:
            if type(e) is UnsupportedMediaType:
                return unsupported_media_type()
            return bad_request(e)
        return unauthorized()
    return method_not_allowed()


def admin_update_user(
    user_id: int, new_user_data: dict[str, str | int], session: scoped_session
) -> tuple[Response, int]:
    """
    update user with given id
    """
    LOGGER.debug(f"admin_update_user: -> new_user_data : {new_user_data} )")
    req_user_data = User.from_json(new_user_data)
    db_user = User.query.filter_by(id=user_id).first()
    LOGGER.debug(f"admin_update_user: -> db_user : {db_user} ")
    if db_user is None:
        return request_error_response("user_not_found"), 400
    db_op_result = update_user(db_user, req_user_data, session=session)
    LOGGER.debug(f"admin_update_user: -> db_op_result : {db_op_result} ")
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(
            success_msg="user_updated", extra={"user": db_user.__json__()}
        ),
        200,
    )


def admin_update_package(
    package_id: int,
    new_package_data: dict[str, str | int | list[int | PackageContent]],
    override_children: bool = False,
) -> tuple[Response, int]:
    """
    update package with given id
    """
    LOGGER.debug(f"admin_update_package: -> new_package_data : {new_package_data} )")
    try:
        req_package_data = Package.from_json(new_package_data)
    except SchemaError as e:
        if e.code == "invalid_package_content":
            if isinstance(new_package_data["package_contents"], list):
                for req_data_pc_content in new_package_data["package_contents"]:
                    try:
                        req_package_content_data = PackageContent.from_json(
                            req_data_pc_content
                        )
                    except SchemaError as e:
                        return request_error_response("invalid_package_content"), 400
                    db_op_pc_result = add_package_content(req_package_content_data)
                    if db_op_pc_result != DBOperationResult.success:
                        return (
                            request_error_response(
                                "db_error", extra=db_op_pc_result.__json__()
                            ),
                            400,
                        )
        req_package_data = Package.from_json(new_package_data)

    db_package = Package.query.filter_by(id=package_id).first()
    LOGGER.debug(f"admin_update_package: -> db_package : {db_package} ")
    if db_package is None:
        return request_error_response("package_not_found"), 400
    if override_children:
        LOGGER.debug(f"admin_update_package: -> override_children : {override_children} ")
        db_package.package_contents = []
    if (req_package_data.package_contents is not None) and (
        req_package_data.package_contents != []
    ):
        LOGGER.debug(
            f"admin_update_package: -> req_package_data.package_contents : {req_package_data.package_contents} "  # noqa
        )
        for package_content in req_package_data.package_contents:
            LOGGER.debug(f"admin_update_package: -> package_content : {package_content} ")
            if isinstance(package_content, PackageContent):
                db_package.package_contents.append(package_content)
            else:
                return request_error_response("invalid_package_content"), 400
    db_op_result = update_package(db_package, req_package_data)
    LOGGER.debug(f"admin_update_package: -> db_op_result : {db_op_result} ")
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(
            success_msg="package_updated", extra={"package": db_package.__json__()}
        ),
        200,
    )


def admin_update_package_content(
    package_content_id: int, new_package_content_data: dict[str, str | int]
) -> tuple[Response, int]:
    """
    update package_content with given id
    """
    LOGGER.debug(
        f"admin_update_package_content: -> new_package_content_data : {new_package_content_data} )"  # noqa
    )
    req_package_content_data = PackageContent.from_json(new_package_content_data)
    db_package_content = PackageContent.query.filter_by(id=package_content_id).first()
    LOGGER.debug(
        f"admin_update_package_content: -> db_package_content : {db_package_content} "
    )
    if db_package_content is None:
        return request_error_response("package_content_not_found"), 400
    db_op_result = update_package_content(db_package_content, req_package_content_data)
    LOGGER.debug(f"admin_update_package_content: -> db_op_result : {db_op_result} ")
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(
            success_msg="package_content_updated",
            extra={"package_content": db_package_content.__json__()},
        ),
        200,
    )


def admin_update_u_package(
    u_package_id: int, new_u_package_data: dict[str, str | int]
) -> tuple[Response, int]:
    """
    update u_package with given id
    """
    LOGGER.debug(f"admin_update_u_package: -> new_u_package_data : {new_u_package_data} )")
    db.session.autoflush = False

    db_u_package = U_Package.query.filter_by(id=u_package_id).first()
    LOGGER.debug(f"admin_update_u_package: -> db_u_package : {db_u_package} ")
    db.session.autoflush = True
    if db_u_package is None:
        return request_error_response("u_package_not_found"), 400
    req_u_package = U_Package.from_json(new_u_package_data)
    LOGGER.debug(f"admin_update_u_package: -> req_u_package_data : {req_u_package} ")
    if req_u_package.base_package is None:
        return request_error_response("base_package_not_found"), 400
    if req_u_package.user_id is None:
        req_u_package.user_id = req_u_package.user.id
    db_op_result = update_u_package(db_u_package, req_u_package)
    LOGGER.debug(f"admin_update_u_package: -> db_op_result : {db_op_result} ")
    if db_op_result is DBOperationResult.success:
        return (
            request_success_response(
                success_msg="u_package_updated",
                extra={"u_package": db_u_package.__json__()},
            ),
            200,
        )
    return request_error_response("db_error", extra=db_op_result.__json__()), 400


def admin_update_u_session(
    u_session_id: int, new_u_session_data: dict[str, str | int]
) -> tuple[Response, int]:
    """
    update u_session with given id
    """
    u_session_data = U_Session.from_json(new_u_session_data)
    db_u_session = U_Session.query.filter_by(id=u_session_id).first()
    if db_u_session is None:
        return request_error_response("u_session_not_found"), 400
    db_user = User.query.filter_by(id=u_session_data.user_id).first()
    if db_user is None:
        return request_error_response("user_not_found"), 400
    db_op_result = update_u_session(db_u_session, u_session_data)
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(
            success_msg="u_session_updated", extra={"u_session": db_u_session.__json__()}
        ),
        200,
    )


@main_blueprint.route(endpoints.URLS.AInfo, methods=["GET"])
def admin_info(m_type: int, m_id: int) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    req_method = request.method
    LOGGER.debug(f"{req_id} - {req_method} {request.url} m_type : {m_type} id : {m_id}")
    if req_method == "GET":
        if (is_admin := get_admin_from_req(request)) is not None:
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            try:
                if m_type == mType.all_models:
                    # TODO: implement admin_info_all_models | admin_register
                    return NotImplemented
                elif m_type == mType.user:
                    return admin_info_user(m_id)
                elif m_type == mType.package:
                    return admin_info_package(m_id)
                elif m_type == mType.package_content:
                    return admin_info_package_content(m_id)
                elif m_type == mType.u_package:
                    return admin_info_u_package(m_id)
                elif m_type == mType.u_session:
                    return admin_info_u_session(m_id)
                return (
                    request_error_response(
                        "unsupported_model_type",
                        extra={
                            "detail": {
                                "supported_model_types": {
                                    "user": mType.user,
                                    "package": mType.package,
                                    "package_content": mType.package_content,
                                    "u_package": mType.u_package,
                                    "u_session": mType.u_session,
                                }
                            }
                        },
                    ),
                    400,
                )
            except SchemaError as schErr:
                LOGGER.debug(f"{req_id} - catched schema error : {schErr}")
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
                return req_data_incomplete()
            except ReqDataErrors.req_data_is_none_or_empty:
                return req_data_is_none_or_empty()
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : {e}")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


def admin_info_user(user_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} user_id : {user_id}")
    if request.method == "GET":
        if (is_admin := get_admin_from_req(request)) is not None:
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            try:
                db_user = get_user_by_id(id=user_id)
                if db_user is None:
                    return request_error_response("user_not_found"), 404
                return (
                    request_success_response(
                        success_msg="success", extra={"user": db_user.__json__()}
                    ),
                    200,
                )
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


def admin_info_package(package_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} package_id : {package_id}")
    if request.method == "GET":
        if (is_admin := get_admin_from_req(request)) is not None:
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            try:
                get_package_by_id = Package.query.filter_by(id=package_id).first()
                if get_package_by_id is None:
                    return request_error_response("package_not_found"), 404
                return (
                    request_success_response(
                        success_msg="success",
                        extra={"package": get_package_by_id.__json__()},
                    ),
                    200,
                )
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()

    return method_not_allowed()


def admin_info_package_content(package_content_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} {package_content_id=}")  # noqa
    if request.method == "GET":
        if (is_admin := get_admin_from_req(request)) is not None:
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            try:
                db_package_content = PackageContent.query.filter_by(
                    id=package_content_id
                ).first()
                if db_package_content is None:
                    return request_error_response("package_content_not_found"), 404
                return (
                    request_success_response(
                        success_msg="success",
                        extra={"package_content": db_package_content.__json__()},
                    ),
                    200,
                )
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


def admin_info_u_package(u_package_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} u_package_id : {u_package_id}")

    if request.method == "GET":
        if (is_admin := get_admin_from_req(request)) is not None:
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            try:
                db_u_package = U_Package.query.filter_by(id=u_package_id).first()
                if db_u_package is None:
                    return request_error_response("u_package_not_found"), 404
                return (
                    request_success_response(
                        success_msg="success",
                        extra={"u_package": db_u_package.__json__()},
                    ),
                    200,
                )
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


def admin_info_u_session(u_session_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} u_session_id : {u_session_id}")
    if request.method == "GET":
        if (is_admin := get_admin_from_req(request)) is not None:
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            try:
                db_u_session = U_Session.query.filter_by(id=u_session_id).first()
                if db_u_session is None:
                    return request_error_response("u_session_not_found"), 404
                return (
                    request_success_response(
                        success_msg="success",
                        extra={"u_session": db_u_session.__json__()},
                    ),
                    200,
                )
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


@main_blueprint.route(endpoints.URLS.ADelete, methods=["DELETE"])
def admin_delete(m_type: int, m_id: int) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} m_type : {m_type} id : {m_id}")
    if request.method == "DELETE":
        if (is_admin := get_admin_from_req(request)) is not None:
            LOGGER.debug(f"{req_id} - admin : {is_admin}")
            try:
                if m_type == mType.all_models:
                    return (
                        request_error_response(
                            "ignored_model_type",
                            extra={
                                "detail": "ignored_model_type",
                                "supported_model_types": {
                                    "user": mType.user,
                                    "package": mType.package,
                                    "package_content": mType.package_content,
                                    "u_package": mType.u_package,
                                    "u_session": mType.u_session,
                                },
                            },
                        ),
                        400,
                    )
                if m_type == mType.user:
                    return admin_delete_user(m_id)
                elif m_type == mType.package:
                    return admin_delete_package(m_id)
                elif m_type == mType.package_content:
                    return admin_delete_package_content(m_id)
                elif m_type == mType.u_package:
                    return admin_delete_u_package(m_id)
                elif m_type == mType.u_session:
                    return admin_delete_u_session(m_id)
                return (
                    request_error_response(
                        "unsupported_model_type",
                        extra={
                            "detail": {
                                "supported_model_types": {
                                    "user": mType.user,
                                    "package": mType.package,
                                    "package_content": mType.package_content,
                                    "u_package": mType.u_package,
                                    "u_session": mType.u_session,
                                }
                            }
                        },
                    ),
                    400,
                )
            except Exception as e:
                LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
                if type(e) is UnsupportedMediaType:
                    return unsupported_media_type()
                return bad_request(e)
        return unauthorized()
    return method_not_allowed()


def admin_delete_user(user_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} user_id : {user_id}")
    db_user = get_user_by_id(id=user_id)
    if db_user is None:
        return request_error_response("user_not_found"), 404
    ret_user_data = {
        "user": db_user.__json__(),
    }
    db_op_result = delete_model(db_user)
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(success_msg="user_deleted", extra=ret_user_data),
        200,
    )


def admin_delete_package(package_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} package_id : {package_id}")
    db_package = get_package_by_id(id=package_id)
    if db_package is None:
        return request_error_response("package_not_found"), 404
    ret_package_data = {
        "package": db_package.__json__(),
    }
    db_op_result = delete_model(db_package)
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(success_msg="package_deleted", extra=ret_package_data),
        200,
    )


def admin_delete_package_content(package_content_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} {package_content_id=}")
    db_package_content = get_package_content_by_id(id=package_content_id)
    if db_package_content is None:
        return request_error_response("package_content_not_found"), 404
    ret_package_content_data = {
        "package_content": db_package_content.__json__(),
    }
    db_op_result = delete_model(db_package_content)
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(
            success_msg="package_content_deleted",
            extra=ret_package_content_data,
        ),
        200,
    )


def admin_delete_u_package(u_package_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} u_package_id : {u_package_id}")
    db_u_package = get_u_package_by_id(id=u_package_id)
    if db_u_package is None:
        return request_error_response("u_package_not_found"), 404
    ret_u_package_data = {
        "u_package": db_u_package.__json__(),
    }
    db_op_result = delete_model(db_u_package)
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(success_msg="u_package_deleted", extra=ret_u_package_data),
        200,
    )


def admin_delete_u_session(u_session_id) -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url} {u_session_id=}")
    db_u_session = get_u_session_by_id(id=u_session_id)
    if db_u_session is None:
        return request_error_response("u_session_not_found"), 404
    ret_u_session_data = {
        "u_session": db_u_session.__json__(),
    }
    db_op_result = delete_model(db_u_session)
    if db_op_result != DBOperationResult.success:
        return request_error_response("db_error", extra=db_op_result.__json__()), 400
    return (
        request_success_response(success_msg="u_session_deleted", extra=ret_u_session_data),
        200,
    )


@main_blueprint.route(endpoints.URLS.ALogin, methods=["GET", "POST"])
def admin_login(content_page=0, get_binded: bool = True) -> tuple[Response, int]:
    content_per_page = 50
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(
        f"{req_id} - {request.method} {request.url} {content_page=} {get_binded=}"
    )  # noqa
    if request.method == "POST":
        is_admin = get_admin_from_req(request)
        LOGGER.debug(f"{req_id} - is_admin : {is_admin}")
        if is_admin:
            db_users = (
                User.query.offset(content_page * content_per_page)
                .limit(content_per_page)
                .all()
            )
            # db_users_ = User.query.all().offset(content_page * content_per_page).limit(content_per_page) # noqa

            return (
                jsonify(
                    {
                        "status": "success",
                        "users": [user.__json__() for user in db_users],
                        "page": content_page,
                    }
                ),
                200,
            )
        return jsonify({"status": "error", "message": "admin_cred_not_found"}), 404
    return unauthorized()


@main_blueprint.route(endpoints.URLS.ULogin, methods=["GET", "POST"])
def user_login() -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "POST":
        try:
            is_user = get_user_from_req(request)
            LOGGER.debug(f"{req_id} - is_user : {is_user}")
            if isinstance(is_user, User):
                LOGGER.debug(f"{req_id} - trying to login")
                if (
                    try_login_response := try_login(
                        is_user, ip_addr=request.remote_addr, flsk_session=session
                    )
                ) is not None:
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
                    elif try_login_response is loginError.session_not_accessable:
                        return (
                            request_error_response("session_not_accessable"),
                            403,
                        )
                    elif try_login_response is False:
                        return (
                            request_error_response("login_failed"),
                            401,
                        )
                    elif try_login_response is True:
                        return (
                            request_success_response(
                                "login_success", extra={"user": is_user.__json__()}
                            ),
                            200,
                        )
        except Exception as e:
            LOGGER.debug(f"{req_id} - catched unknown error : -> {type(e)=} ,{e=} ")
            if type(e) is UnsupportedMediaType:
                return unsupported_media_type()
            return jsonify({"status": "error", "message": "login_failed"}), 400
        return jsonify({"status": "error", "message": "user_cred_not_found"}), 404
    return unauthorized()


@main_blueprint.route(endpoints.URLS.UInfo, methods=["GET"])
def user_info() -> tuple[Response, int]:
    req_id = generate_req_id(remote_addr=request.remote_addr)
    LOGGER.debug(f"{req_id} - {request.method} {request.url}")
    if request.method == "GET":
        is_user = get_user_from_req(request)
        LOGGER.debug(f"{req_id} - is_user : {is_user}")
        if isinstance(is_user, User):
            LOGGER.debug(f"{req_id} - trying to get user info")
            return (
                request_success_response(
                    "user_info_success", extra={"user": is_user.__json__()}
                ),
                200,
            )
        return jsonify({"status": "error", "message": "user_cred_not_found"}), 404
    return method_not_allowed()


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

    # TODO: this should be called session_id or something like that
    if hasattr(session, "req_id"):
        return session["req_id"]
    req_id = str(remote_addr) + "_" + str(uuid4())
    session["req_id"] = req_id
    return req_id
