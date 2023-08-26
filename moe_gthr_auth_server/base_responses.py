from flask import jsonify, Response


def request_error_response(error_msg="unkown_error") -> Response:
    return jsonify({"status": "error", "message": error_msg})


def request_success_response(success_msg=None) -> Response:
    return jsonify({"status": "success", "message": success_msg})
