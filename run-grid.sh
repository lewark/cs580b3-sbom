#!/bin/bash

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
    SOURCE_URL="${SOFTWARE[$SOFTWARE_NAME]}"
    for MODEL in "${MODELS[@]}"; do
        for ITERATION in $(seq 1 $ITERATIONS); do
            OUTPUT_DIR="$LOG_BASE_DIR/$SOFTWARE_NAME/iteration$ITERATION"
            mkdir -p "$OUTPUT_DIR"
            export OUTPUT_DIR
            LOG_FILE="$OUTPUT_DIR/${MODEL//:/_}_analysis.log"
            
            echo "Running model: $MODEL on $SOFTWARE_NAME (Iteration $ITERATION)"
            ./run-agent.sh --docker "$MODEL" "$SOURCE_URL" 2>&1 | tee "$LOG_FILE"
            sleep 1
        done
    done
done
