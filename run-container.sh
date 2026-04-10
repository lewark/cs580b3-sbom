#!/bin/sh

ENGINE="podman"
if [ "$1" = "--docker" ] || [ "$1" = "--podman" ]; then
    ENGINE="${1#--}"
    shift
fi

# NOTE: this currently uses host networking, since I ran into issues with the
# "host.containers.internal" address. Later on we can troubleshoot this or try using Skua instead.

EXTRA_OPTS=""
if [ -n "$CONTAINER_NAME" ]; then
    EXTRA_OPTS="--name $CONTAINER_NAME"
fi
if [ -f ".env" ]; then
    EXTRA_OPTS="$EXTRA_OPTS --env-file=.env"
fi


if [ ! -d logs ]; then
    mkdir logs
fi

$ENGINE run -i --init --rm --volume $PWD/logs:/data/logs --volume $PWD/.cache:/root/.cache --network=host $EXTRA_OPTS "$@"
