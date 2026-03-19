#!/bin/sh

# NOTE: this currently uses host networking, since I ran into issues with the
# "host.containers.internal" address. Later on we can troubleshoot this or try using Skua instead.

podman run -i --volume $PWD:/data --network=host python bash $@
