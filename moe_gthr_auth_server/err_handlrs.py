from flask import Blueprint, jsonify, Response

error_blueprint = Blueprint("error_blueprint", __name__)


@error_blueprint.errorhandler(400)
def bad_request(error=None) -> tuple[Response, int]:
    if error is not None:
        return jsonify({"status": "error", "message": "bad_request", "error": str(error)}), 400
    return jsonify({"status": "error", "message": "bad_request"}), 400


@error_blueprint.errorhandler(401)
def unauthorized(error=None) -> tuple[Response, int]:
    return jsonify({"status": "error", "message": "unauthorized"}), 401


@error_blueprint.errorhandler(404)
def not_found(error=None) -> tuple[Response, int]:
    return jsonify({"status": "error", "message": "not_found"}), 404


@error_blueprint.errorhandler(415)
def unsupported_media_type(error=None) -> tuple[Response, int]:
    return jsonify({"status": "error", "message": "unsupported_media_type"}), 415
