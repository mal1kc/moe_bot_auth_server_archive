from __future__ import annotations

import datetime
import logging
from functools import partial
from typing import Any

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.sessions import SessionMixin  # noqa
from flask.wrappers import Response
from werkzeug.wrappers import Response as BaseResponse

from moe_bot_auth_server.config.endpoints import (
    ADMIN_CONTROL_URLS,
    _create_formatible_admin_control_urls,
)
from moe_bot_auth_server.cryption import create_sha512_hash, make_password_hash
from moe_bot_auth_server.database_ops import (
    Admin,
    Package,
    PackageContent,
    U_Package,
    U_Session,
    User,
    create_model_from_req_form,
    delete_model,
    get_all_admins,
    get_all_content_values,
    get_all_package_contents,
    get_all_packages,
    get_all_u_packages,
    get_all_u_sessions,
    get_all_users,
    get_package_by_id,
    get_package_content_by_id,
    get_u_package_by_id,
    get_u_session_by_id,
    get_user_by_id,
    update_package_content_from_req_form,
    update_package_from_req_form,
    update_u_package_from_req_form,
    update_u_session_from_req_form,
    update_user_from_req_form,
)
from moe_bot_auth_server.enums import DBOperationResult, mTypeStr
from moe_bot_auth_server.err_handlrs import method_not_allowed
from moe_bot_auth_server.main_app import generate_req_id

"""
One Page Admin Control Panel

- capabilities
    - model listing
    - model creation
    - model deletion
    - model update
    - uses internal API to perform actions with redirections
"""

# Blueprint
admin_control_blueprint = Blueprint(
    "admin_control",
    __name__,
)

LOGGER = logging.getLogger("admin_control")

url_for_main = partial(
    url_for,
    "admin_control.admin_control_main",
)


@admin_control_blueprint.route("/favicon.ico")
def favicon():
    return current_app.send_static_file("favicon.ico")


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AAbout, methods=["GET"])
def admin_control_about() -> Response | str | tuple[Response, int]:
    return render_template("about.html")


def parse_char_list_to_str_list(char_list: list[str] | str) -> list[str]:
    # example chr_list : "[" "'" "l" "o" "g" ... "'" , "'" ... "l" "'" , "]"
    sentence_seprated_char_list = []
    str_list = []
    for char in char_list:
        if char == "'" or char == "[":
            continue
        elif char == ",":
            str_list.append("".join(sentence_seprated_char_list))
            sentence_seprated_char_list.clear()
        elif char == "]":
            str_list.append("".join(sentence_seprated_char_list))
            sentence_seprated_char_list.clear()
        else:
            sentence_seprated_char_list.append(char)
    return str_list


@admin_control_blueprint.route(
    ADMIN_CONTROL_URLS.AMain,
    methods=["GET"],
    defaults={"messages": [""]},
)
@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AMain + "<messages>", methods=["GET"])
def admin_control_main(
    messages: None | str = None,
) -> Response | str | tuple[Response, int]:
    # example messages : "[" "'" "l" "o" "g" ... "'" , "'" ... "l" "'" , "]"
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "GET":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        users = get_all_users()
        template_vars = {
            "enumerate": enumerate,
            "mTypeStr": mTypeStr,
            "endpoints": _create_formatible_admin_control_urls(),
            "utc_now": datetime.datetime.utcnow(),
            "users": users,
            "messages": parse_char_list_to_str_list(messages)
            if messages is not None
            else [],
        }
        return render_template(
            "admin_control.html",
            **template_vars,
        )
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.ALogin, methods=["POST"])
def admin_control_login() -> BaseResponse | str | tuple[Response, int]:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        admin = login_check(username, password)
        if admin is False:
            return render_template("login.html", messages=["username or password is wrong"])
        return redirect(url_for_main(messages=["logged in"]))
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.ALogout, methods=["GET"])
def admin_control_logout() -> BaseResponse | Response | tuple[Response, int]:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "GET":
        session["username"] = None
        session["logged_in"] = False
        return redirect(url_for("admin_control.admin_control_main"))
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AList, methods=["GET"])
def admin_control_list(
    model_type: str,
) -> Any:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "GET":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        if model_type not in mTypeStr.__members__:
            return redirect(url_for_main(messages=["model type is wrong"]))
        model_type = mTypeStr[model_type]
        render_template_w_tvars = partial(
            render_template,
            "list.html",
            enumerate=enumerate,
            endpoints=_create_formatible_admin_control_urls(),
            mTypeStr=mTypeStr,
            model_type=model_type,
            utc_now=datetime.datetime.utcnow(),
        )
        if model_type == mTypeStr.user:
            users = get_all_users()
            return render_template_w_tvars(models=users)
        elif model_type == mTypeStr.package:
            packages = get_all_packages()
            return render_template_w_tvars(models=packages)
        elif model_type == mTypeStr.package_content:
            package_contents = get_all_package_contents()
            return render_template_w_tvars(models=package_contents)
        elif model_type == mTypeStr.u_package:
            u_packages = get_all_u_packages()
            return render_template_w_tvars(models=u_packages)
        elif model_type == mTypeStr.u_session:
            u_sessions = get_all_u_sessions()
            return render_template_w_tvars(models=u_sessions)
        else:
            return redirect(url_for_main(messages=["model type is wrong"]))


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AInfo, methods=["GET"])
def admin_control_info(model_type: str, model_id: int) -> Any:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "GET":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        if model_type not in mTypeStr.__members__:
            return redirect(
                render_template("admin_control.html", messages=["model type is wrong"])
            )
        if model_id < 0:
            return redirect(
                render_template("admin_control.html", messages=["model id is wrong"])
            )
        model_type = mTypeStr[model_type]
        form_method = "POST"  # UPDATE # only get,post supported fck it
        form_action = url_for(
            "admin_control.admin_control_update",
            model_type=model_type,
            model_id=model_id,
        )
        render_detail_template_w_tvars = partial(
            render_template,
            "detail.html",
            enumerate=enumerate,
            endpoints=_create_formatible_admin_control_urls(),
            mTypeStr=mTypeStr,
            model_type=model_type,
            form_method=form_method,
            form_action=form_action,
            form_type="update",
            utc_now=datetime.datetime.utcnow(),
        )
        if model_type == mTypeStr.user:
            user = get_user_by_id(model_id)
            if user is None:
                return redirect(url_for_main(messages=["user not found"]))
            packages = get_all_packages()
            return render_detail_template_w_tvars(
                model=user,
                base_packages=packages,
            )
        elif model_type == mTypeStr.package:
            package = get_package_by_id(model_id)
            if package is None:
                return redirect(url_for_main(messages=["package not found"]))
            package_contents = get_all_package_contents()
            return render_detail_template_w_tvars(
                model=package,
                package_contents=package_contents,
            )
        elif model_type == mTypeStr.package_content:
            package_content = get_package_content_by_id(model_id)

            if package_content is None:
                return redirect(url_for_main(messages=["package content not found"]))
            content_values = get_all_content_values()
            return render_detail_template_w_tvars(
                model=package_content,
                content_values=content_values,
            )
        elif model_type == mTypeStr.u_package:
            u_package = get_u_package_by_id(model_id)
            if u_package is None:
                redirect(url_for_main(messages=["u_package not found"]))
            packages = get_all_packages()
            users = get_all_users()
            return render_detail_template_w_tvars(
                model=u_package,
                base_packages=packages,
                users=users,
            )
        elif model_type == mTypeStr.u_session:
            u_session = get_u_session_by_id(model_id)
            users = get_all_users()
            if u_session is None:
                redirect(url_for_main(messages=["u_session not found"]))
            return render_detail_template_w_tvars(
                model=u_session,
                users=users,
            )
        else:
            return redirect(url_for_main(messages=["model type is wrong"]))
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.ACreate, methods=["GET", "POST"])
def admin_control_create(model_type: str) -> Any:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "GET":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        if model_type not in mTypeStr.__members__:
            return redirect(url_for_main(messages=["model type is wrong"]))
        model_type = mTypeStr[model_type]
        form_action = url_for(
            "admin_control.admin_control_create",
            model_type=model_type,
        )
        formattible_endpoints = _create_formatible_admin_control_urls()
        form_method = "POST"  # CREATE
        template_vars = {
            "form_type": "create",
            "form_method": form_method,
            "form_action": form_action,
            "endpoints": formattible_endpoints,
            "model_type": model_type,
            "mTypeStr": mTypeStr,
        }

        if model_type == mTypeStr.user:
            template_vars["base_packages"] = get_all_packages()
        elif model_type == mTypeStr.package:
            template_vars["package_contents"] = get_all_package_contents()
        elif model_type == mTypeStr.package_content:
            template_vars["content_values"] = get_all_content_values()
        elif model_type == mTypeStr.u_package:
            template_vars["base_packages"] = get_all_packages()
            template_vars["users"] = get_all_users()

        return render_template(
            "detail.html",
            **template_vars,
        )
    elif request.method == "POST":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        if model_type not in mTypeStr.__members__:
            return redirect(url_for_main(messages=["model type is wrong"]))
        model_type = mTypeStr[model_type]

        if model_type == mTypeStr.user:
            user = User()
            db_result = create_model_from_req_form(user, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=["user could not be created", "error: " + str(db_result)]
                    )
                )
            return redirect(url_for_main(messages=["user created"]))
        elif model_type == mTypeStr.package:
            package = Package()
            db_result = create_model_from_req_form(package, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "package could not be created",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["package created"]))

        elif model_type == mTypeStr.package_content:
            package_content = PackageContent()
            db_result = create_model_from_req_form(package_content, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "package content could not be created",
                            "error: " + str(db_result),
                        ],
                    )
                )
            return redirect(
                url_for_main(
                    messages=["package content created"],
                )
            )
        elif model_type == mTypeStr.u_package:
            u_package = U_Package()
            db_result = create_model_from_req_form(u_package, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "u_package could not be created",
                            "error: " + str(db_result),
                        ],
                    )
                )
            return redirect(url_for_main(messages=["u_package created"]))
        elif model_type == mTypeStr.u_session:
            u_session = U_Session()
            db_result = create_model_from_req_form(u_session, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "u_session could not be created",
                            "error: " + str(db_result),
                        ],
                    )
                )
            return redirect(url_for_main(messages=["u_session created"]))
        else:
            return redirect(url_for_main(messages=["model type is wrong"]))
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AUpdate, methods=["POST"])
def admin_control_update(model_type: str, model_id: int) -> Any:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "POST":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        if model_type not in mTypeStr.__members__:
            return render_template("admin_control.html", messages=["model type is wrong"])
        if model_id < 0:
            return render_template("admin_control.html", messages=["model id is wrong"])
        model_type = mTypeStr[model_type]
        if model_type == mTypeStr.user:
            user = get_user_by_id(model_id)
            if user is None:
                return redirect(url_for_main(messages=["user not found"]))
            db_result = update_user_from_req_form(user, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=["user could not be updated", "error: " + str(db_result)]
                    )
                )
            return redirect(url_for_main(messages=["user updated"]))
        elif model_type == mTypeStr.package:
            package = get_package_by_id(model_id)
            if package is None:
                return redirect(url_for_main(messages=["package not found"]))
            db_result = update_package_from_req_form(package, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "package could not be updated",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["package updated"]))
        elif model_type == mTypeStr.package_content:
            package_content = get_package_content_by_id(model_id)
            if package_content is None:
                return redirect(url_for_main(messages=["package content not found"]))
            db_result = update_package_content_from_req_form(package_content, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "package content could not be updated",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["package content updated"]))
        elif model_type == mTypeStr.u_package:
            u_package = get_u_package_by_id(model_id)
            if u_package is None:
                return redirect(url_for_main(messages=["u_package not found"]))
            db_result = update_u_package_from_req_form(u_package, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "u_package could not be updated",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["u_package updated"]))
        elif model_type == mTypeStr.u_session:
            u_session = get_u_session_by_id(model_id)
            if u_session is None:
                return redirect(url_for_main(messages=["u_session not found"]))
            db_result = update_u_session_from_req_form(u_session, request.form)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "u_session could not be updated",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["u_session updated"]))


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.ADelete, methods=["POST"])
def admin_control_delete(model_type: str, model_id: int) -> Any:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "POST":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        if model_type not in mTypeStr.__members__:
            return redirect(url_for_main(messages=["model type is wrong"]))
        if model_id < 0:
            return redirect(url_for_main(messages=["model id is wrong"]))
        model_type = mTypeStr[model_type]
        if model_type == mTypeStr.user:
            db_user = get_user_by_id(model_id)
            if db_user is None:
                return redirect(url_for_main(messages=["user not found"]))
            db_result = delete_model(db_user)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=["user could not be deleted", "error: " + str(db_result)]
                    )
                )
            return redirect(url_for_main(messages=["user deleted"]))
        elif model_type == mTypeStr.package:
            db_package = get_package_by_id(model_id)
            if db_package is None:
                return redirect(url_for_main(messages=["package not found"]))
            db_result = delete_model(db_package)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "package could not be deleted",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["package deleted"]))
        elif model_type == mTypeStr.package_content:
            db_package_content = get_package_content_by_id(model_id)
            if db_package_content is None:
                return redirect(url_for_main(messages=["package content not found"]))
            db_result = delete_model(db_package_content)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "package content could not be deleted",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["package content deleted"]))
        elif model_type == mTypeStr.u_package:
            db_u_package = get_u_package_by_id(model_id)
            if db_u_package is None:
                return redirect(
                    url_for_main(
                        messages=["u_package not found"],
                    )
                )
            # TODO: maybe user_incld=True sometimes ?
            info_json = db_u_package.__json__(user_incld=False)
            db_result = delete_model(db_u_package)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "u_package could not be deleted",
                            "error: " + str(db_result),
                        ]
                    )
                )
            info_message = json_to_message(info_json)
            return redirect(url_for_main(messages=["u_package deleted", info_message]))
        elif model_type == mTypeStr.u_session:
            db_u_session = get_u_session_by_id(model_id)
            if db_u_session is None:
                return redirect(url_for_main(messages=["u_session not found"]))
            if db_u_session.access:
                return redirect(
                    url_for_main(
                        messages=[
                            "u_session is active, cannot be deleted",
                        ]
                    )
                )
            db_result = delete_model(db_u_session)
            if db_result != DBOperationResult.success:
                return redirect(
                    url_for_main(
                        messages=[
                            "u_session could not be deleted",
                            "error: " + str(db_result),
                        ]
                    )
                )
            return redirect(url_for_main(messages=["u_session deleted"]))
        else:
            return redirect(url_for_main(messages=["model type is wrong"]))
    return method_not_allowed()


def login_check(username: str | None, password: str | None) -> bool | Admin:
    LOGGER.info("checking login data")
    is_logged_in = login_check_session(session)
    if is_logged_in is not False:
        return is_logged_in
    elif password is None or username is None:
        return False
    else:
        admins = get_all_admins()
        if username not in [admin.name for admin in admins]:
            return False
        possible_admins = [admin for admin in admins if admin.name == username]
        if len(possible_admins) != 1:
            return False
        possible_admin = possible_admins[0]
        if make_password_hash(password) == possible_admin.password_hash:
            session["username"] = possible_admin.name
            session["logged_in"] = create_sha512_hash(
                (possible_admin.name + possible_admin.password_hash)
            )
            return possible_admin
        else:
            return False


def login_check_session(session: "SessionMixin") -> bool | Admin:
    if session.get("logged_in") is None or session.get("logged_in") is False:
        LOGGER.info("session is not logged in")
        return False
    else:
        username = session.get("username")
        login_data = session.get("logged_in")
        if username is None or login_data is None:
            return False
        admins = get_all_admins()
        if username not in [admin.name for admin in admins]:
            return False
        possible_admin = [admin for admin in admins if admin.name == username][0]
        if (
            create_sha512_hash((possible_admin.name + possible_admin.password_hash))
            == login_data
        ):
            return possible_admin
        else:
            return False


def json_to_message(data: dict[str, Any]) -> str:
    message = "{"
    remove = "password_hash", "id"
    replace_chars = "[", "]", "'", ","
    replace = "<<", ">>", " ", "|"
    # this remove_chars are for better looking message
    # TODO: maybe update parse_char_list_to_str_list change later
    for key in data:
        if key not in remove:
            message += f"{key} : {data[key]}"
    for indx in range(len(replace_chars)):
        message = message.replace(replace_chars[indx], replace[indx])
    message += "}"
    return message
