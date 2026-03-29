#!/bin/bash

# Define the models to test
MODELS=(
    "llama3"
    "mistral"
    # Add more models to the array here
)

# Define the product sources as an associative array: ["product_name"]="source_url"
declare -A PRODUCTS=(
    ["tomcat"]="https://archive.apache.org/dist/tomcat/tomcat-10/v10.1.19/src/apache-tomcat-10.1.19-src.tar.gz"
    # Add more product names and URLs here
)

# Base log directory
LOG_DIR="logs"

# Ensure base log directory exists
mkdir -p "$LOG_DIR"

echo "Starting testbed execution..."

# Iterate over each product
for PRODUCT_NAME in "${!PRODUCTS[@]}"; do
    PRODUCT_URL="${PRODUCTS[$PRODUCT_NAME]}"
    PRODUCT_LOG_DIR="$LOG_DIR/$PRODUCT_NAME"

    # Create product-specific log directory
    mkdir -p "$PRODUCT_LOG_DIR"
    
    echo "========================================"
    echo "Product: $PRODUCT_NAME"
    echo "Source URL: $PRODUCT_URL"
    echo "Log Directory: $PRODUCT_LOG_DIR"
    echo "========================================"

    # Iterate over each model
    for MODEL in "${MODELS[@]}"; do
        echo "  -> Running model: $MODEL on $PRODUCT_NAME"
        
        # Define log file path
        LOG_FILE="$PRODUCT_LOG_DIR/${MODEL}_analysis.log"
        
        # Execute the agent and capture output
        # You can add --docker or --podman here if needed: ./run-agent.sh --docker "$MODEL" "$PRODUCT_URL"
        ./run-agent.sh --docker "$MODEL" "$PRODUCT_URL" > "$LOG_FILE" 2>&1
        
        echo "  -> Finished $MODEL on $PRODUCT_NAME. Logs saved to $LOG_FILE"
    done
done

echo "All tests completed!"
