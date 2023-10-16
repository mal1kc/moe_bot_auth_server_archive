#!/bin/env bash
# "set -xe" means: verbose, -x print commands and -e exit on error
set -e

app_name="moe_bot_auth_server"
app_version="$(poetry version --short)"

docker_cmd="docker"
alt_docker_cmd="podman"
active_docker_cmd=$docker_cmd
img_name="$app_name"
img_tag="$app_version"

# first check if alt_docker_cmd is available and use it if it is otherwise use docker_cmd

# create new config file
mk_config_file() {
	cp ./config/config.toml.example ./config/config.toml

	sed -i "s/DEBUG=true/DEBUG=false/g" ./config/config.toml
	sed -i "s/LOG_LEVEL=\"DEBUG\"/LOG_LEVEL=\"INFO\"/g" ./config/config.toml

	# remove SECRET_KEY from config file
	sed -i "/SECRET_KEY/d" ./config/config.toml
	cat ./config/config.toml
}

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
mk_config_file
$active_docker_cmd build -t "$img_name:$img_tag" -f ./Dockerfile .
$active_docker_cmd build -t "$img_name:latest" -f ./Dockerfile .
echo "Container image built"
git clean -df
exit 0
