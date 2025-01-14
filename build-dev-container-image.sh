#!/bin/env bash
# "set -xe" means: verbose, -x print commands and -e exit on error
set -e

app_name="moe_bot_auth_server"
app_version="$(poetry version --short)"

docker_cmd="docker"
alt_docker_cmd="podman"
active_docker_cmd=$docker_cmd
img_name="$app_name"
img_tag="dev$app_version"

# first check if alt_docker_cmd is available and use it if it is otherwise use docker_cmd
#
# create new config file

if command -v $alt_docker_cmd &>/dev/null; then
	echo "$alt_docker_cmd is available using it"
	active_docker_cmd=$alt_docker_cmd
elif command -v $docker_cmd &>/dev/null; then
	echo "$alt_docker_cmd is not available but $docker_cmd is using it"
	active_docker_cmd=$docker_cmd
else
	echo "$alt_docker_cmd and $docker_cmd are not available exiting with error"
	exit 1
fi

if [ -z "$app_version" ]; then
	echo "Could not get app version exiting with error"
	exit 1
fi

# if image exists remove it
if $active_docker_cmd image inspect "$img_name:$img_tag" &>/dev/null; then
	echo "Removing existing container image with tag dev$app_version"
	$active_docker_cmd image rm "$img_name:$img_tag"
	echo "Existing container image removed"
fi

echo "Building container image"
echo "clean up git untracked files"
git clean -df
cp ./config/config.toml.example ./config/config.toml
$active_docker_cmd build -t "$img_name:$img_tag" -f ./Dockerfile-dev .
echo "Container image built"
git clean -df
if [ -f ./config/config.toml ]; then
	rm ./config/config.toml
fi
exit 0
