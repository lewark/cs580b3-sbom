# CS 580B3 SBOM

This program analyzes software repositories to produce vulnerability risk assessments. It uses two components: the Ollama server that runs the LLM, and the containerized agent client that runs the software analysis.

## Installing Ollama

To install Ollama on a machine, you can either run the setup command provided [here](https://ollama.com/download), or you can directly download the software binaries and extract them to a folder. Unlike the quick installation command, the latter strategy works on machines where you lack root access. See the manual installation instructions for [Linux](https://docs.ollama.com/linux), [macOS](https://docs.ollama.com/macos), or [Windows](https://docs.ollama.com/windows).

## Setting up the container

The containerization scripts are intended to be run on Linux. Clone this repository on the machine that will host the containers.

We have provided a Dockerfile to set up the testing environment. To build a custom image that includes necessary system utilities and pre-downloads the Apache Tomcat testing target, run:

```bash
# Build the specialized container image
docker build -t llm-agent-testbed .

# Or, if using Podman:
podman build -t llm-agent-testbed .
```

## Connecting to Ollama from another machine

The machine that runs Ollama does not have to be the same one that runs the container the agent will interact with. To set up the two on different machines, use the following process. You may skip this section if running Ollama on the same machine.

First, on the machine that will host the Ollama server, run `export OLLAMA_HOST=0.0.0.0:11434` before starting the server. This will allow other machines on the network to connect.

On the machine that runs the containerized agent, create a `.env` file under this directory and enter the following, replacing `IP_ADDRESS` with the address of the machine running Ollama:

```
OLLAMA_HOST=IP_ADDRESS:11434
```

Additionally, the `OLLAMA_API_KEY` variable is required to use web search, and can also be placed inside `.env`.
The scripts will automatically pass environment variables within the `.env` file into
the container.


## Running the agent

Run `./run-agent.sh MODEL [SOURCE_URL]` to start the agent, replacing `MODEL` with the name of the model to run (e.g. `qwen3.5:9b`). You can optionally provide a `SOURCE_URL` to a `.tar.gz` codebase distribution which will be downloaded and analyzed.

You can optionally specify the container engine to use (either `--podman` or `--docker`) before the model name. By default, Podman is used.

```bash
# Run with Podman (default)
./run-agent.sh qwen3.5:9b
# Or:
./run-agent.sh --podman qwen3.5:9b

# Run with Docker and analyze a specific source distribution
./run-agent.sh --docker qwen3.5:9b https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.57/src/apache-tomcat-8.5.57-src.tar.gz
```

## Running the advanced tool agent

A more advanced version of the agent has been implemented using LangChain (`ollama_tool_agent.py`). This version has the ability to not only run raw shell commands, but dynamically parse large JSON SBOM files using local RAG, and query the web using DuckDuckGo to match CVE details during the triage process.

To use the advanced agent:
1. Ensure your container environment is up to date with the latest `requirements.txt` which will install the necessary LangChain libraries (`./setup-container.sh`).
2. Inside your Ollama host, pull an embedding model to be used by the RAG system:
   ```bash
   ollama pull nomic-embed-text
   ```
3. To execute the tool agent, simply edit the `run-agent.sh` script to change `sbom.ollama_agent` to `sbom.ollama_tool_agent` at the end of the script before executing it.

## TL;DR: Execution Order

If you want to get up and running quickly, follow this execution order:

1. **Start Ollama**: Make sure your Ollama instance is running (locally or remotely via `.env` configured host).
2. **Setup Environment**: Run `./setup-container.sh` once to build the necessary environment and install dependencies. To use a more robust environment, build the Dockerfile: `docker build -t llm-agent-testbed .`
3. **Run Agent**: Run `./run-agent.sh <MODEL> [SOURCE_URL]` (e.g., `./run-agent.sh qwen3.5:9b https://example.com/source.tar.gz`) to start the analysis. Remember to include `--docker` before the model name if you aren't using Podman.

## Testbed

To automate the execution of multiple agents across different software packages and models, you can use the `run-grid.sh` testbed script. Logs are automatically categorized in a `logs/<software_name>/iteration<N>/` directory structure.

You will need to make sure you run `ollama pull` for each model listed within the testbed configuration, or the script will fail due to the missing model.

### Configuration

The testbed utilizes a configuration file (by default `grid_config.sh`). You can define your test matrix as follows:

```bash
# Configuration for run-grid.sh

# List of models to test
MODELS=( 
    "ministral-3:14b-cloud" 
    "qwen3.5:397b-cloud" 
)

# Associative array of software to test, format: ["name"]="url"
declare -A SOFTWARE=(
    ["tomcat"]="https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.57/src/apache-tomcat-8.5.57-src.tar.gz"
)

# Number of iterations to run for each model/software combination
ITERATIONS=1
```

### Running the Testbed

You can run the grid testing script with the default configuration:

```bash
./run-grid.sh --podman

# Or:
./run-grid.sh --docker
```

Alternatively, you can provide a custom configuration file as an argument to maintain multiple testing profiles:

```bash
./run-grid.sh --podman custom_config.sh
```

## Analyzing results

After producing outputs from the model, you can analyze the results using the following steps:

1. Parse the logs using the `sbom.logs.parser` tool, as shown in `README_logs.md`
2. Run the LLM-J (`sbom.llm_j.analyze_logs`), confusion matrix (`sbom.llm_j.confusion_matrix`), and plotting (`sbom.llm_j.aggregate_results`) scripts, as described in `README_llm_j.md`
