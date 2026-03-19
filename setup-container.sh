#!/bin/sh

./run-container.sh bash -c "echo start && cd /data && echo 'hello' && ./setup.sh"
