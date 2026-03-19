#!/bin/sh

podman run -i --volume $PWD:/data python bash /data/setup.sh
