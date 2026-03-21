#!/bin/sh

ENGINE_ARG=""
if [ "$1" = "--docker" ] || [ "$1" = "--podman" ]; then
    ENGINE_ARG="$1"
    shift
fi

MODEL=$1

if [ ! -d logs ]; then
    mkdir logs
fi

./run-container.sh $ENGINE_ARG bash -c "cd /data/tomcat/apache-tomcat-8.5.57 && /data/venv/bin/python3 /data/ollama-agent.py $MODEL"
