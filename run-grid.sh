#!/bin/bash

MODELS=( "qwen3.5:9b" "llama3.2:3b" )
SOFTWARE=( "https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.57/src/apache-tomcat-8.5.57-src.tar.gz" )
ITERATIONS=1

for SOURCE_URL in "$SOFTWARE[@]"; do
    for MODEL in "$MODELS[@]"; do
        for ITERATION in {1..$ITERATIONS}; do
            ./run-agent.sh --podman $MODEL $SOURCE_URL
            sleep 1
        done
    done
done
