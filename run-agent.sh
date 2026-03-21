#!/bin/sh

ENGINE_ARG=""
if [ "$1" = "--docker" ] || [ "$1" = "--podman" ]; then
    ENGINE_ARG="$1"
    shift
fi

MODEL=$1
SOURCE_URL=$2

if [ ! -d logs ]; then
    mkdir logs
fi

# If a source URL is provided, download and extract it right before running the agent
SETUP_CMD=""
TARGET_DIR="/data"
if [ -n "$SOURCE_URL" ]; then
    TARGET_DIR="/data/target_code"
    # Download the distribution to a temp file and extract it directly into target_code
    SETUP_CMD="echo \"[Container] Downloading source from $SOURCE_URL...\" && rm -rf $TARGET_DIR && mkdir -p $TARGET_DIR && wget -qO /tmp/src_dist.tar.gz \"$SOURCE_URL\" && echo \"[Container] Extracting source code to $TARGET_DIR...\" && tar -xzf /tmp/src_dist.tar.gz -C $TARGET_DIR --strip-components=1 && echo \"[Container] Extraction complete.\" && "
fi

CONTAINER_NAME="sbom_agent_$$"
export CONTAINER_NAME

cleanup() {
    echo -e "\n[Agent] Terminating and cleaning up container $CONTAINER_NAME..."
    # Always use the assigned engine to gracefully stop or force remove
    ENGINE="podman"
    if [ "$ENGINE_ARG" = "--docker" ]; then
        ENGINE="docker"
    fi
    $ENGINE rm -f "$CONTAINER_NAME" >/dev/null 2>&1
    exit 1
}

# Trap Ctrl+C (SIGINT) and run the cleanup function
trap cleanup INT

echo "Starting container execution for model: $MODEL (Container: $CONTAINER_NAME)"
./run-container.sh $ENGINE_ARG bash -c "${SETUP_CMD}echo \"[Agent] Starting Ollama Python agent...\" && cd $TARGET_DIR && /data/venv/bin/python3 -u /data/ollama-agent.py $MODEL"

