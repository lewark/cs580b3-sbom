#!/bin/sh

# NOTE: this currently uses host networking, since I ran into issues with the
# "host.containers.internal" address. Later on we can troubleshoot this or try using Skua instead.

EXTRA_OPTS=""
if [ -f ".env" ]; then
    EXTRA_OPTS="--env-file=.env"
fi
	

podman run -i --volume $PWD:/data --network=host $EXTRA_OPTS python "$@"
