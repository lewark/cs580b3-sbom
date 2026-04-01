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

# Ensure the Dockerfile is built using the correct engine before running the agent
BUILD_ENGINE="podman"
if [ "$ENGINE_ARG" = "--docker" ]; then
    BUILD_ENGINE="docker"
fi
echo "[Agent] Ensuring 'llm-agent-testbed' image is built..."
$BUILD_ENGINE build -q -t llm-agent-testbed .

# If a source URL is provided, download and extract it right before running the agent
SETUP_CMD=""
EXTRA_MOUNT=""
TARGET_DIR="/data"
SOFTWARE_DIR="./source_files"
if [ -n "$SOURCE_URL" ]; then
    TARGET_DIR="/data/target_code"

    SOFTWARE_FILENAME=$(basename "$SOURCE_URL")
    SOFTWARE_PATH="$SOFTWARE_DIR/$SOFTWARE_FILENAME"

    mkdir -p $SOFTWARE_DIR

    # Download the distribution to a temp file and extract it directly into target_code
    if [ ! -f $SOFTWARE_PATH ]; then
        echo "Downloading source from $SOURCE_URL..."
        wget -qO "$SOFTWARE_PATH" "$SOURCE_URL"
    fi

    SETUP_CMD="echo \"[Container] Extracting source code to $TARGET_DIR...\" && mkdir -p $TARGET_DIR && tar -xzf /$SOFTWARE_FILENAME -C $TARGET_DIR --strip-components=1 && echo \"[Container] Extraction complete.\" && "
    EXTRA_MOUNT="--volume $SOFTWARE_PATH:/$SOFTWARE_FILENAME:ro"
fi

ENV_OPTS="-e PYTHONPATH=/scripts"
if [ -n "$OUTPUT_DIR" ]; then
    ENV_OPTS="$ENV_OPTS -e OUTPUT_DIRECTORY=/data/$OUTPUT_DIR"
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


# Always ensure cleanup runs on regular exit, failure, or Ctrl+C
trap cleanup EXIT INT TERM

echo "Starting container execution for model: $MODEL (Container: $CONTAINER_NAME)"
./run-container.sh $ENGINE_ARG $EXTRA_MOUNT $ENV_OPTS llm-agent-testbed bash -c "${SETUP_CMD}echo \"[Agent] Starting Ollama Python agent...\" && cd $TARGET_DIR && python3 -m sbom.ollama_agent $MODEL"
