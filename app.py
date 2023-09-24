import os
import sys

from moe_gthr_auth_server import create_app


def start_server(host: str, port: int, args: dict | None = None):
    if args is None:  # mutable guard
        args = {"certfile": "config/ssl/cert.pem", "keyfile": "config/ssl/key.pem"}
    app.run(host=host, port=port, ssl_context=(args["certfile"], args["keyfile"]))


def start_debug_server(host: str, port: int, args: dict | None = None):
    if args is None:  # mutable guard
        args = {"use_reloader": True}
    app.run(debug=True, host=host, port=port, **args)


def is_debug_mode():
    argv_debug = [
        debug_arg
        for debug_arg in sys.argv
        if debug_arg.startswith("--debug")
        or debug_arg.startswith("-d")
        or debug_arg.startswith("--dev")
        or debug_arg.startswith("-dev")
    ]
    if argv_debug:
        return True
    env_debug = os.environ.get("FLASK_ENV") in [
        "development",
        "debug",
        "d",
        "dev",
    ] or os.environ.get("FLASK_DEBUG") in ["1", "true", "True", "t", "T"]
    return env_debug


def get_port():
    argv_port = [
        port_arg
        for port_arg in sys.argv
        if port_arg.startswith("--port=") or port_arg.startswith("-p=")
    ]
    if argv_port:
        return int(argv_port[0].split("=")[1])
    env_port = os.environ.get("PORT", 5000)
    return int(env_port)


if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("HOST", "0.0.0.0")
    port = get_port()
    is_debug = is_debug_mode()
    print(
        (("-" * 80) + "\n")
        + f"Starting server on {host}:{port} in {'debug' if is_debug else 'production'} mode"  # noqa: E501
        + ("\n" + ("-" * 80))
    )
    if is_debug:
        start_debug_server(host, port)
        sys.exit(0)
    start_server(host, port)
    sys.exit(0)
