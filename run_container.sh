#!/bin/env sh
PORT=2402
podman run --rm --env PORT=$PORT -p $PORT:$PORT moe_gthr_auth_server:latest
