# CS 580B3 SBOM

This program analyzes software repositories to produce vulnerability risk assessments. It uses two components: the Ollama server that runs the LLM, and the containerized agent client that runs the software analysis.

## Installing Ollama

To install Ollama on a machine, you can either run the setup command provided [here](https://ollama.com/download), or you can directly download the software binaries and extract them to a folder. Unlike the quick installation command, the latter strategy works on machines where you lack root access. See the manual installation instructions for [Linux](https://docs.ollama.com/linux), [macOS](https://docs.ollama.com/macos), or [Windows](https://docs.ollama.com/windows).

## Setting up the container

The containerization scripts are intended to be run on Linux. Clone this repository on the machine that will host the containers. Then, run `./setup-container.sh` to set up the Python virtual environment and install the software dependencies.

For a more robust testing environment, we have provided a Dockerfile. To build a custom image that includes necessary system utilities and pre-downloads the Apache Tomcat testing target, run:

```bash
# Build the specialized container image
docker build -t llm-agent-testbed .
```

After building the image, ensure that `run-container.sh` is updated to utilize the new image (`llm-agent-testbed` instead of `python`). Similarly, `run-agent.sh` no longer needs to use the `/venv/bin/python3` execution path since dependencies are built globally into the Docker image.

## Connecting to Ollama from another machine

The machine that runs Ollama does not have to be the same one that runs the container the agent will interact with. To set up the two on different machines, use the following process.

First, on the machine that will host the Ollama server, run `export OLLAMA_HOST=0.0.0.0:11434` before starting the server. This will allow other machines on the network to connect.

On the machine that runs the containerized agent, create a `.env` file under this directory and enter the following, replacing `IP_ADDRESS` with the address of the machine running Ollama:

```
OLLAMA_HOST=IP_ADDRESS:11434
```

The scripts will automatically pass environment variables within the `.env` file into
the container.

## Running the agent

Run `./run-agent.sh MODEL [SOURCE_URL]` to start the agent, replacing `MODEL` with the name of the model to run (e.g. `qwen3.5:9b`). You can optionally provide a `SOURCE_URL` to a `.tar.gz` codebase distribution which will be downloaded and analyzed.

You can optionally specify the container engine to use (either `--podman` or `--docker`) before the model name. By default, Podman is used.

```bash
# Run with Podman (default)
./run-agent.sh qwen3.5:9b
./run-agent.sh --podman qwen3.5:9b

# Run with Docker and analyze a specific source distribution
./run-agent.sh --docker qwen3.5:9b https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.57/src/apache-tomcat-8.5.57-src.tar.gz
```

## Running the advanced tool agent

A more advanced version of the agent has been implemented using LangChain (`ollama-tool-agent.py`). This version has the ability to not only run raw shell commands, but dynamically parse large JSON SBOM files using local RAG, and query the web using DuckDuckGo to match CVE details during the triage process.

To use the advanced agent:
1. Ensure your container environment is up to date with the latest `requirements.txt` which will install the necessary LangChain libraries (`./setup-container.sh`).
2. Inside your Ollama host, pull an embedding model to be used by the RAG system:
   ```bash
   ollama pull nomic-embed-text
   ```
3. To execute the tool agent, simply edit the `run-agent.sh` script to change `/data/ollama-agent.py` to `/data/ollama-tool-agent.py` at the end of the script before executing it.

## TL;DR: Execution Order

If you want to get up and running quickly, follow this execution order:

1. **Start Ollama**: Make sure your Ollama instance is running (locally or remotely via `.env` configured host).
2. **Setup Environment**: Run `./setup-container.sh` once to build the necessary environment and install dependencies. To use a more robust environment, build the Dockerfile: `docker build -t llm-agent-testbed .`
3. **Run Agent**: Run `./run-agent.sh <MODEL> [SOURCE_URL]` (e.g., `./run-agent.sh qwen3.5:9b https://example.com/source.tar.gz`) to start the analysis. Remember to include `--docker` before the model name if you aren't using Podman.
