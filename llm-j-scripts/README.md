# LLM-J CVE Log Analyzer

This tool parses local JSON logs, extracts Common Vulnerabilities and Exposures (CVE) IDs, enriches them using the [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) database, and leverages a local Large Language Model via Ollama to perform an automated judgment/analysis (LLM-J) of the security context.

## Prerequisites

1.  **Python 2.7 or Python 3.x**
2.  **Ollama**: Installed and running locally.
    *   Download from [Ollama's official website](https://ollama.com).
3.  **Cloud Model**: You need an Ollama cloud model, such as one from the [Ollama Cloud Search](https://ollama.com/search?c=tools&c=cloud). For example, pull `gpt-oss:120b-cloud` (or `qwen3.5:397b-cloud`).
    ```bash
    ollama pull gpt-oss:120b-cloud
    ```
4.  **Dependencies**: The script primarily uses standard libraries, but requires `requests` for API calls.
    ```bash
    pip install requests
    ```

## Project Structure

Ensure your workspace directory looks like this:

```
├── logs/
│   ├── parsed-logs/
│   │   ├── parsed_ministral-3_14b_...json
│   │   └── ...
│   ├── llm-j-analysis-logs/
│   │   ├── (Analysis output files will be created here)
├── llm-j-scripts/
│   ├── analyze_logs.py
│   └── README.md
```

## Usage

1. Start up your Ollama daemon locally (usually runs in the background automatically if installed as a service, or run `ollama serve` in a terminal).
2. Ensure your parsed logs are placed in the `../logs/parsed-logs/` directory.
3. Change to the `llm-j-scripts` directory and execute the script. You can run it in two different modes:

### Default Parsing
Run the script without arguments to parse the root of the default `../logs/parsed-logs/` directory:

```bash
cd llm-j-scripts
python analyze_logs.py
```

### Directory Parsing (Recommended)
You can target a specific directory representing an application (e.g., `../logs/parsed-logs/tomcat`). The script will recursively traverse the folder, find all `.json` files within its subfolders (like `iteration1`, `iteration2`, etc.), and mirror the directory structure when saving outputs to `../logs/llm-j-analysis-logs/`:

```bash
cd llm-j-scripts
python analyze_logs.py ../logs/parsed-logs/tomcat
```
*Outputs will be saved dynamically to `../logs/llm-j-analysis-logs/tomcat/iterationX/llm-j-...`*

## How It Works

1.  **Extraction**: Reads all `.json` files inside the `../logs/parsed-logs/` directory. It automatically parses lists of vulnerabilities or falls back to applying regex matching (`CVE-\d{4}-\d{4,7}`) to find referenced CVE identifiers.
2.  **Enrichment**: Dynamically fetches the latest CISA Vulnrichment JSON record directly from the `cisagov/vulnrichment` main branch via raw GitHub URLs.
3.  **LLM-J Analysis**: Acts as an "AI Judge". It transmits the candidate LLM's previously extracted JSON context and the CISA enrichment ground truth data to your configured Ollama model. It prompts the model to score the candidate AI out of 10 regarding accuracy, provide reasoning for hallucinations, and assign an overall accuracy metric.
4.  **Structured Output**: Outputs individual structured JSON files (prefixed with `llm-j-`) and saves them to the `../logs/llm-j-analysis-logs/` directory.
