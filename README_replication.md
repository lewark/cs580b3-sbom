# Replication instructions

## Datasets

Download Vulnrichment by cloning it from GitHub:

```bash
git clone --depth=1 https://github.com/cisagov/vulnrichment
```

Additionally download the [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds) to a directory:

```bash
mkdir nvd
cd nvd

for year in {2002..2026}; do
    wget https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${year}.json.gz
done

wget https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz
wget https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz
```

## Software Dependencies

### Setting up Ollama

You will need to create an Ollama account at https://ollama.com/ to use the cloud models referenced in the results.
Additionally, some of these models such as GLM-5.1 necessitate a $20/month Pro subscription, as does the overall token usage to run the full set.

See the Ollama documentation for setup instructions.
Windows: https://docs.ollama.com/windows
Linux: https://docs.ollama.com/linux
macOS: https://docs.ollama.com/macos

With the Ollama CLI, make sure the server is listening by running `ollama serve`, and log in to your cloud account by running `ollama login`. Pull the required models as follows:

```bash
ollama pull ministral-3:14b-cloud
ollama pull qwen3.5:397b-cloud
ollama pull nemotron-3-super:cloud
ollama pull glm-5.1:cloud
ollama pull qwen3-next:80b-cloud
ollama pull gemma4:31b-cloud
```

### Python libraries

Run the `./setup.sh` script to create a virtual environment and install the Python dependencies. You will need to ensure the `venv` module is installed first (on Linux distributions, it is often included in packages such as `python3-venv`).

### Container runtime

You will also need to install the CLI for either the [Docker](https://www.docker.com/) or [Podman](https://podman.io/) container runtime. They should be available in the repositories of most Linux distributions, or you can see their website for instructions on other platforms.

### Running ChromaDB

Ensure ChromaDB is running using the following command:

```bash
source venv/bin/activate
./run-chroma.sh
```

## Agent

Use the following steps to run the agents for each part. Replace the `--podman` argument with `--docker` if using Docker rather than Podman.
For more information, see the main `README.md` file.

Note that `nemotron-3-super:cloud` was skipped for RQ2 and 3 due to it running into issues on the task for RQ1, so it can be excluded by commenting its line out in `grid_config.sh` for the later parts.

```bash
source venv/bin/activate
# Move original results to another directory
mv logs logs.old

# RQ1
./run-grid.sh --podman
mkdir -p results/standard-prompt/
mv logs results/standard-prompt/non-tooling

# RQ2
./run-grid.sh --tooling --podman
mv logs results/standard-prompt/tooling

# RQ3
# Without SBOM access
./run-grid.sh --cot --podman
mkdir -p results/chain-of-thought-prompt/
mv logs results/chain-of-thought-prompt/non-tooling
# With SBOM access
./run-grid.sh --cot --tooling --podman
mv logs results/chain-of-thought-prompt/tooling

# For the following steps
mv results logs
```

## Log parsing

Extract the vulnerability lists from the LLM output using the following script. The `README_logs.md` file contains more discussion on this tool.

```bash
source venv/bin/activate
python3 -m sbom.logs.parser logs/
```

## LLM-J

Next, run LLM-J on the parsed agent output. See `README_llm_j.md` for more information.

```bash
export NVD_DIR=./nvd VULNRICHMENT_DIR=./vulnrichment
source venv/bin/activate
python3 -m sbom.llm_j.analyze_logs logs/parsed-logs/
```

Generate figures and run the statistical tests on the LLM-J output using the following steps. See `README_statistics.md` for details.

```bash
mv figures figures.old
source venv/bin/activate
python3 -m sbom.llm_j.aggregate_results logs/llm-j-analysis-logs
```

## Confusion matrices + F1

To produce the F1 score for vulnerability presence/absence and the confusion matrices, run these commands:

```bash
export NVD_DIR=./nvd VULNRICHMENT_DIR=./vulnrichment
source venv/bin/activate
python3 -m sbom.llm_j.confusion_matrix logs/
```
