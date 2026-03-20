#!/bin/sh

MODEL=$1

if [ ! -d logs ]; then
    mkdir logs
fi

./run-container.sh bash -c "cd /data/tomcat/apache-tomcat-8.5.57 && /data/venv/bin/python3 /data/ollama-agent.py $MODEL"
