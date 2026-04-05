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
    ["continuum"]="https://archive.apache.org/dist/continuum/binaries/apache-continuum-1.4.2-bin.tar.gz"
    ["archiva"]="https://archive.apache.org/dist/archiva/2.0.1/binaries/apache-archiva-2.0.1-bin.tar.gz"
    ["log4j"]="https://archive.apache.org/dist/logging/log4j/1.2.17/log4j-1.2.17.tar.gz"
    ["wink"]="https://archive.apache.org/dist/logging/log4j/1.2.17/log4j-1.2.17.tar.gz"
)

# Number of iterations to run for each model/software combination
ITERATIONS=1