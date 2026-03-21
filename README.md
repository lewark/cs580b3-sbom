# CS 580B3 SBOM

This program analyzes software repositories to produce vulnerability risk assessments. It uses two components: the Ollama server that runs the LLM, and the containerized agent client that runs the software analysis.

## Installing Ollama

To install Ollama on a machine, you can either run the setup command provided [here](https://ollama.com/download), or you can directly download the software binaries and extract them to a folder. Unlike the quick installation command, the latter strategy works on machines where you lack root access. See the manual installation instructions for [Linux](https://docs.ollama.com/linux), [macOS](https://docs.ollama.com/macos), or [Windows](https://docs.ollama.com/windows).

## Setting up the container

The containerization scripts are intended to be run on Linux. Clone this repository on the machine that will host the containers. Then, run `./setup-container.sh` to set up the Python virtual environment and install the software dependencies.

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

Run `./run-agent.sh MODEL` to start the agent, replacing `MODEL` with the name of the model to run (e.g. `qwen3.5:9b`).

You can optionally specify the container engine to use (either `--podman` or `--docker`) before the model name. By default, Podman is used.

```bash
# Run with Podman (default)
./run-agent.sh qwen3.5:9b
./run-agent.sh --podman qwen3.5:9b

# Run with Docker
./run-agent.sh --docker qwen3.5:9b
```
