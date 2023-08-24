#!/bin/bash

# "set -xe" means: verbose, -x print commands and -e exit on error
set -e

app_name="moe_gthr_auth_server"
app_version="$(poetry version --short)"

docker_cmd="docker"
alt_docker_cmd="podman"
active_docker_cmd=$docker_cmd
img_name="$app_name"
img_tag="dev$app_version"

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

if [ -z "$app_version" ]
then
    echo "Could not get app version exiting with error"
    exit 1
fi

# if image exists remove it
if $active_docker_cmd image inspect "$img_name:$img_tag" &> /dev/null
then
    echo "Removing existing container image with tag dev$app_version"
    $active_docker_cmd image rm "$img_name:$img_tag"
    echo "Existing container image removed"
fi

echo "Building container image"
$active_docker_cmd build -t "$img_name:$img_tag" -f ./Dockerfile .
echo "Container image built"
exit 0
