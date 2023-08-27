from flask import jsonify, Response


def request_error_response(error_msg="unkown_error", extra: dict | None = None) -> Response:
    if extra:
        return jsonify({"status": "error", "message": error_msg, **extra})
    return jsonify({"status": "error", "message": error_msg})


def request_success_response(success_msg=None, extra: dict | None = None) -> Response:
    if extra:
        return jsonify({"status": "success", "message": success_msg, **extra})
    return jsonify({"status": "success", "message": success_msg})
