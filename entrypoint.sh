#!/usr/bin/env sh

flask -A moe_bot_auth_server cli initdb
# # https serve
# exec gunicorn --bind :8080 --workers "1" --threads 8 --timeout 0 "moe_bot_auth_server:create_app()" --keyfile ./config/key.pem --certfile ./config/cert.pem

# # http serve
exec gunicorn
