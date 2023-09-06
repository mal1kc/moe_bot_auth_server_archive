from flask import Response, jsonify


def request_error_response(error_msg="unkown_error", extra: dict | None = None) -> Response:
    if extra:
        return jsonify({"status": "error", "message": error_msg, **extra})
    return jsonify({"status": "error", "message": error_msg})


def request_success_response(success_msg=None, extra: dict | None = None) -> Response:
    if extra:
        return jsonify({"status": "success", "message": success_msg, **extra})
    return jsonify({"status": "success", "message": success_msg})


def req_data_incomplete(error=None, extra: dict | None = None) -> tuple[Response, int]:
    ret_data = {"status": "error", "message": "request_data_incomplete"}
    if error is not None:
        ret_data["error"] = str(error)
    if extra:
        ret_data.update(extra)
    return (
        jsonify(ret_data),
        400,
    )


def req_data_is_none_or_empty(error=None) -> tuple[Response, int]:
    _ = error
    return request_error_response("request_data_is_none_or_empty"), 400
