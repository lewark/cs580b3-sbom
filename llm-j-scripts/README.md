# LLM-J CVE Log Analyzer

This tool parses local JSON logs, extracts Common Vulnerabilities and Exposures (CVE) IDs, enriches them using the [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) database, and leverages a local Large Language Model via Ollama to perform an automated judgment/analysis (LLM-J) of the security context.

## Prerequisites

1.  **Python 3.8+**
2.  **Ollama**: Installed and running locally.
    *   Download from [Ollama's official website](https://ollama.com).
3.  **Cloud Model**: You need an Ollama cloud model, such as one from the [Ollama Cloud Search](https://ollama.com/search?c=tools&c=cloud). For example, pull `qwen3.5:397b-cloud`.
    ```bash
    ollama pull qwen3.5:397b-cloud
    ```
4.  **Dependencies**: The script primarily uses standard libraries, but requires `requests` for API calls.
    ```bash
    pip install requests
    ```

## Project Structure

Ensure your workspace directory looks like this:

```
├── logs/
│   ├── qwen3.5_9b_2026-03-19_212942.json
│   ├── ...
├── analyze_logs.py
└── README.md
```

## Usage

1. Start up your Ollama daemon locally (usually runs in the background automatically if installed as a service, or run `ollama serve` in a terminal).
2. Execute the script:

```bash
python analyze_logs.py
```

## How It Works

1.  **Extraction**: Reads all `.json` files inside the `logs/` directory and applies regex matching (`CVE-\d{4}-\d{4,7}`) to find referenced CVE identifiers.
2.  **Enrichment**: Dynamically fetches the latest CISA Vulnrichment JSON record directly from the `cisagov/vulnrichment` main branch via raw GitHub URLs.
3.  **LLM-J Analysis**: Transmits the collected log context and CISA enrichment data to your configured `qwen3.5:397b-cloud` model using Ollama. It prompts the model to summarize the vulnerability, evaluate EPSS/Severity, deduce impact based on contexts, and recommend mitigations.
4.  **Structured Output**: Outputs a standard, well-formatted `llmj_analysis_results.json` file aggregating all findings into one artifact.
