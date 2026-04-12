# LLM-J CVE Log Analyzer

This tool parses local JSON logs, extracts Common Vulnerabilities and Exposures (CVE) IDs, and leverages a local Large Language Model via Ollama to perform an automated judgment/analysis (LLM-J) of the security context. It complements vulnerability information using the [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) project and optionally the [National Vulnerability Database](https://nvd.nist.gov).

## Rationale

Evaluating individual model responses for accuracy and quality would be overly time consuming. LLM-J allows us to automate this process.

In our case, a common issue that crops up with outputs from the LLM-based vulnerability assessment model is that incorrect vulnerabilities are hallucinated. Even vulnerabilities that exist may refer to software that is not relevant to the project in question. Through a second evaluation pass, an LLM can look at the details of a vulnerability and assess how accurate the previous stage really was.

As a later extension to this tool, we may add additional LLM-J metrics that capture the quality of reasoning traces, but we chose not to at this time to reduce the risk of the judge getting stuck or missing important information about the output.

## Prerequisites

1.  **Python 3.x**
2.  **Ollama**: Installed and running locally.
    *   Download from [Ollama's official website](https://ollama.com).
3.  **Cloud Model**: We recommend using an Ollama cloud model, such as one from the [Ollama Cloud Search](https://ollama.com/search?c=tools&c=cloud). For example, pull `gpt-oss:120b-cloud` (or `qwen3.5:397b-cloud`).
    ```bash
    ollama pull gpt-oss:120b-cloud
    ```
    Note you will also need to create an account at [the Ollama website](https://www.ollama.com/) and log in by running `ollama login`.
4.  **Dependencies**: The `analyze_logs` script primarily uses standard libraries, but requires `requests` for API calls. The `aggregate_results` script uses `numpy`, `pandas`, and `matplotlib`. You may additionally want to use a virtual environment to separate the installed libraries from the system-provided Python packages.
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt 
    ```

## Project Structure

Ensure your workspace directory looks like this. The `llm-j-analysis-logs` directory will be created automatically if nonexistent.

```
├── logs/
│   ├── parsed-logs/
│   │   ├── parsed_ministral-3_14b_...json
│   │   └── ...
│   ├── llm-j-analysis-logs/
│   │   ├── ...
│   │   └── (Analysis output files will be created here)
├── sbom/
│   ├── llm_j/
│   │   ├── aggregate_results.py
│   │   └── analyze_logs.py
│   └── ...
```

## Usage

1. Start up your Ollama daemon locally (usually runs in the background automatically if installed as a service, or run `ollama serve` in a terminal).
2. Ensure your parsed logs are placed in the `./logs/parsed-logs/` directory.
3. Execute the script. You can run it in two different modes:

### Default Parsing
Run the script without arguments to parse the root of the default `./logs/parsed-logs/` directory:

```bash
python -m sbom.llm_j.analyze_logs
```

You must either set the NVD_PATH environment variable to a directory containing NVD data feed files, or the NVD_API_KEY variable to a valid API key. To obtain an API key for the National Vulnerability Database, use [this form](https://nvd.nist.gov/developers/request-an-api-key).

### Directory Parsing (Recommended)
You can target a specific directory representing an application (e.g., `./logs/parsed-logs/tomcat`). The script will recursively traverse the folder, find all `.json` files within its subfolders (like `iteration1`, `iteration2`, etc.), and mirror the directory structure when saving outputs to `./logs/llm-j-analysis-logs/`:

```bash
cd llm-j-scripts
python -m sbom.llm_j.analyze_logs ./logs/parsed-logs/tomcat
```
*Outputs will be saved dynamically to `logs/llm-j-analysis-logs/tomcat/iterationX/llm-j-...`*

## How It Works

1.  **Extraction**: Reads all `.json` files inside the `./logs/parsed-logs/` directory. It automatically parses lists of vulnerabilities or falls back to applying regex matching (`CVE-\d{4}-\d{4,7}`) to find referenced CVE identifiers.
2.  **Enrichment**: Dynamically fetches the latest CISA Vulnrichment JSON record directly from the `cisagov/vulnrichment` main branch via raw GitHub URLs.
3.  **LLM-J Analysis**: Acts as an "AI Judge". It transmits the candidate LLM's previously extracted JSON context and the CISA enrichment ground truth data to your configured Ollama model. It prompts the model to score the candidate AI out of 10 regarding accuracy, provide reasoning for hallucinations, and assign an overall accuracy metric.
4.  **Structured Output**: Outputs individual structured JSON files (prefixed with `llm-j-`) and saves them to the `./logs/llm-j-analysis-logs/` directory.

## Results

Running the `analyze_logs` script on the model logs produces output like this for each identified vulnerability:

```json
{
    "source_log": "parsed_qwen3.5_397b-cloud_2026-03-21_045613.json",
    "cve_id": "CVE-2024-34750",
    "vulnrichment_status": "Found",
    "llmj_analysis": {
        "score": 2,
        "reasoning": "The analysis incorrectly labels the CVE as an information disclosure flaw, only mentions the 8.5.x versions, omits the primary 9.x, 10.x, and 11.x affected ranges, and provides no severity data or correct SSVC decision, deviating significantly from the ground truth.",
        "accuracy": "Low"
    }
}
```

The 'score' value for each vulnerability ranges from 1 to 10 and describes how accurate the LLM-As-Judge perceived its analysis to be.
To get a better idea of typical scores per model, running the `aggregate_results` script on those output files will collect mean, standard deviation, and count:

| Model                  | Mean     | Standard deviation | # of measurements |
| :--------------------- | -------: | -----------------: | ----------------: |
| ministral-3_14b-cloud  | 1.833333 |           0.372678 |                 6 |
| nemotron-3-super_cloud | 1.333333 |           0.471405 |                 3 |
| qwen3.5_397b-cloud     | 1.714286 |           0.589015 |                14 |

Ultimately, the mean score produced for all three models was very low, due to a large number of inaccurate vulnerabilities being output.
This is likely because relying on intrinsic knowledge is not enough: the models need to have more comprehensive tools available to them to be able to properly analyze the codebase.
The script also produces box plots. As we work on getting additional results, charts will become more useful.

## Charting

To produce a summary of the LLM-J logs per model, run the `aggregate_results` script, passing in the directory to process:

```bash
python -m sbom.llm_j.aggregate_results ./logs/llm-j-analysis-logs/
```

This will output charts and ANOVA results, along with mean and standard deviation of the LLM-J scores for each model.

## Confusion Matrix Script

An additional script produces the confusion matrix displaying model SSVC classifications against ground-truth SSVC decisions. This plot can be generated using the following command:

```
python3 -m sbom.llm_j.confusion_matrix ./logs/parsed-logs
```

## AI Disclosure

Google Gemini was used to assist in the development of the `analyze_logs` script and the agent that originally produced the logs.
