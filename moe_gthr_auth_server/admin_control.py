from __future__ import annotations
import datetime
import logging

from typing import Any

from flask import (
    Blueprint,
    Response,
    current_app,
    render_template,
    request,
    session,
    url_for,
    redirect,
)
from flask.sessions import SessionMixin  # noqa

from moe_gthr_auth_server.cryption import create_sha512_hash, make_password_hash
from moe_gthr_auth_server.database_ops import (
    Admin,
    get_all_admins,
    get_all_users,
    get_package_by_id,
    get_package_content_by_id,
    get_u_package_by_id,
    get_u_session_by_id,
    get_user_by_id,
    update_user,
)
from moe_gthr_auth_server.enums import mTypeStr
from moe_gthr_auth_server.err_handlrs import method_not_allowed
from moe_gthr_auth_server.main_app import generate_req_id
from moe_gthr_auth_server.config.endpoints import (
    ADMIN_CONTROL_URLS,
    _create_formatible_admin_control_urls,
)

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
admin_control_blueprint = Blueprint("admin_control", __name__, template_folder="templates")

LOGGER = logging.getLogger("app")


@admin_control_blueprint.route("/favicon.ico")
def favicon():
    return current_app.send_static_file("favicon.ico")


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AAbout, methods=["GET"])
def admin_control_about() -> Response | str | tuple[Response, int]:
    return render_template("about.html")


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AMain, methods=["GET"])
def admin_control_main() -> Response | str | tuple[Response, int]:
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
        }
        return render_template(
            "admin_control.html",
            **template_vars,
        )
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.ALogin, methods=["POST"])
def admin_control_login() -> Response:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        admin = login_check(username, password)
        if admin is False:
            return render_template("login.html", messages=["username or password is wrong"])

        return redirect(url_for("admin_control.admin_control_main"))
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.ALogout, methods=["GET"])
def admin_control_logout() -> Response:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "GET":
        session["username"] = None
        session["logged_in"] = False
        return redirect(url_for("admin_control.admin_control_main"))
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AInfo, methods=["GET"])
def admin_control_info(model_type: str, model_id: int) -> Any:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "GET":
        admin = login_check_session(session)
        if admin is False:
            return render_template("login.html")
        if model_type not in mTypeStr.__members__:
            return render_template("admin_control.html", messages=["model type is wrong"])
        if model_id < 0:
            return render_template("admin_control.html", messages=["model id is wrong"])
        model_type = mTypeStr[model_type]
        form_method = "POST"  # UPDATE # only get,post supported fck it
        form_action = url_for(
            "admin_control.admin_control_update",
            model_type=model_type,
            model_id=model_id,
        )
        formattible_endpoints = _create_formatible_admin_control_urls()
        template_vars = {
            "form_method": form_method,
            "form_action": form_action,
            "endpoints": formattible_endpoints,
            "model_type": model_type,
            "mTypeStr": mTypeStr,
        }  # model independent endpoints -> always returns to template
        if model_type == mTypeStr.user:
            user = get_user_by_id(model_id)

            if user is None:
                return render_template("admin_control.html", messages=["user not found"])
            return render_template(
                "detail.html",
                model=user,
                **template_vars,
            )
        elif model_type == mTypeStr.package:
            package = get_package_by_id(model_id)

            if package is None:
                return render_template("admin_control.html", messages=["package not found"])
            return render_template("detail.html", model=package, **template_vars)
        elif model_type == mTypeStr.package_content:
            package_content = get_package_content_by_id(model_id)

            if package_content is None:
                return render_template(
                    "admin_control.html", messages=["package content not found"]
                )
            return render_template(
                "detail.html",
                model=package_content,
                **template_vars,
            )
        elif model_type == mTypeStr.u_package:
            u_package = get_u_package_by_id(model_id)
            if u_package is None:
                return render_template(
                    "admin_control.html",
                    messages=["u_package not found"],
                )
            return render_template(
                "detail.html",
                model=u_package,
                **template_vars,
            )
        elif model_type == mTypeStr.u_session:
            u_session = get_u_session_by_id(model_id)
            if u_session is None:
                return render_template(
                    "admin_control.html", messages=["u_session not found"]
                )
            return render_template(
                "detail.html",
                model=u_session,
                **template_vars,
            )
        else:
            return render_template("admin_control.html", messages=["model type is wrong"])
    return method_not_allowed()


@admin_control_blueprint.route(ADMIN_CONTROL_URLS.AUpdate, methods=["PUT"])
def admin_control_update(model_type: str, model_id: int) -> Any:
    req_id = generate_req_id(request.remote_addr)
    LOGGER.info(f"Request ID: {req_id} - url: {request.url}")
    if request.method == "PUT":
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
                return render_template("admin_control.html", messages=["user not found"])
            user.name = request.form.get("name")
            user.password_hash = make_password_hash(request.form.get("password"))
            user.package_id = int(request.form.get("package_id"))
            user.discord_id = request.form.get("discord_id")
            update_user(user)


def login_check(username: str, password: str) -> bool | Admin:
    LOGGER.info("checking login data")
    is_logged_in = login_check_session(session)
    if is_logged_in is not False:
        return is_logged_in
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
