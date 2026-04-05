#!/bin/bash

ENGINE_ARG="--podman"
TOOLING_ARG=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --docker|--podman)
            ENGINE_ARG="$1"
            shift
            ;;
        --tooling)
            TOOLING_ARG="--tooling"
            shift
            ;;
        *)
            # First positional argument not starting with -- is the config file
            break
            ;;
    esac
done

# Use the provided config file or default to grid_config.sh
CONFIG_FILE="${1:-grid_config.sh}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file '$CONFIG_FILE' not found."
    exit 1
fi

# Source the configuration configurations (MODELS, SOFTWARE, ITERATIONS)
source "$CONFIG_FILE"

LOG_BASE_DIR="logs"

for SOFTWARE_NAME in "${!SOFTWARE[@]}"; do
    export SOFTWARE_NAME
    SOURCE_URL="${SOFTWARE[$SOFTWARE_NAME]}"
    for MODEL in "${MODELS[@]}"; do
        for ITERATION in $(seq 1 $ITERATIONS); do
            OUTPUT_DIR="$LOG_BASE_DIR/$SOFTWARE_NAME/iteration$ITERATION"
            mkdir -p "$OUTPUT_DIR"
            export OUTPUT_DIR
            LOG_FILE="$OUTPUT_DIR/${MODEL//:/_}_analysis.log"
            
            echo "Running model: $MODEL on $SOFTWARE_NAME (Iteration $ITERATION)"
            if [ -n "$TOOLING_ARG" ]; then
                ./run-agent.sh $ENGINE_ARG $TOOLING_ARG "$MODEL" "$SOURCE_URL" 2>&1 | tee "$LOG_FILE"
            else
                ./run-agent.sh $ENGINE_ARG "$MODEL" "$SOURCE_URL" 2>&1 | tee "$LOG_FILE"
            fi
            sleep 1
        done
    done
done
