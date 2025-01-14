from flask import Blueprint, Response, jsonify

from .base_responses import request_error_response

error_blueprint = Blueprint("error_blueprint", __name__)


@error_blueprint.errorhandler(400)
def bad_request(error=None) -> tuple[Response, int]:
    if error is not None:
        return (
            jsonify({"status": "error", "message": "bad_request", "error": str(error)}),
            400,
        )
    return request_error_response("bad_request"), 400


@error_blueprint.errorhandler(401)
def unauthorized(error=None) -> tuple[Response, int]:
    _ = error
    return request_error_response("unauthorized"), 401


@error_blueprint.errorhandler(404)
def not_found(error=None) -> tuple[Response, int]:
    _ = error
    return request_error_response("not_found"), 404


@error_blueprint.errorhandler(415)
def unsupported_media_type(error=None) -> tuple[Response, int]:
    _ = error
    return request_error_response("unsupported_media_type"), 415


@error_blueprint.errorhandler(405)
def method_not_allowed(error=None) -> tuple[Response, int]:
    _ = error
    return request_error_response("method_not_allowed"), 405


@error_blueprint.errorhandler(500)
def internal_server_error(error=None) -> tuple[Response, int]:
    _ = error
    return request_error_response("internal_server_error"), 500


@error_blueprint.route("/404")
def not_found_error() -> tuple[Response, int]:
    return not_found()
