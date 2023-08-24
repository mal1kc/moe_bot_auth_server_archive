#!/bin/env sh

set -e

PORT=2402
CONTAINER_NAME="moe_gthr_auth_server"
CONTAINER_TAG="dev$(poetry version --short)"
CONTAINER_DEF_PORT=8080

docker_cmd="docker"
alt_docker_cmd="podman"
active_docker_cmd=$docker_cmd
container_tag="dev$app_version"

if ! command -v $docker_cmd &> /dev/null
then
    echo "$docker_cmd could not be found, trying $alt_docker_cmd"
    active_docker_cmd=$alt_docker_cmd
fi
if ! command -v $alt_docker_cmd &> /dev/null
then
    echo "$docker_cmd and $alt_docker_cmd could not be found exiting with error"
    exit 1
fi

if [ -z "$CONTAINER_TAG" ]
then
    echo "Could not get container tag exiting with error"
    exit 1
fi

# if image not exists call build script
if ! $active_docker_cmd image inspect $CONTAINER_NAME:$CONTAINER_TAG &> /dev/null
then
    echo "Container image not found, building it"
    ./.pre-commit-hooks/build-container-image.sh
fi

$active_docker_cmd run --rm --env PORT=$PORT -p $PORT:$CONTAINER_DEF_PORT --name $CONTAINER_NAME $CONTAINER_NAME:$CONTAINER_TAG
