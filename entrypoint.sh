#!/usr/bin/env sh

flask -A moe_gthr_auth_server resetdb
# https serve
# exec gunicorn --bind :8080 --workers "1" --threads 8 --timeout 0 "moe_gthr_auth_server:create_app()" --keyfile ./config/key.pem --certfile ./config/cert.pem
# http serve
exec gunicorn --bind :8080 --workers "1" --threads 8 --timeout 0 "moe_gthr_auth_server:create_app()"
