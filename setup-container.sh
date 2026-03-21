#!/bin/sh

ENGINE_ARG=""
if [ "$1" = "--docker" ] || [ "$1" = "--podman" ]; then
    ENGINE_ARG="$1"
    shift
fi

./run-container.sh $ENGINE_ARG bash -c "echo start && cd /data && echo 'hello' && ./setup.sh"
