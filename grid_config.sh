# Configuration for run-grid.sh

# List of models to test
MODELS=( 
    "ministral-3:14b-cloud" 
    "qwen3.5:397b-cloud" 
    "nemotron-3-super:cloud"
)

# Associative array of software to test, format: ["name"]="url"
declare -A SOFTWARE=(
    ["tomcat"]="https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.57/src/apache-tomcat-8.5.57-src.tar.gz"
)

# Number of iterations to run for each model/software combination
ITERATIONS=1