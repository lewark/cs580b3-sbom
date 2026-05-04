# Statistics script

To generate plots of the LLM-J results and output statistics describing them, run the following commands.

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

unzip logs.zip
python3 -m sbom.llm_j.aggregate_results logs/llm-j-analysis-logs/
```

This will output the following:
- Box plots with the LLM-J scores for each model
- Bar charts listing how many vulnerabilities each model reported
- Kruskal-Wallis tests indicating if LLM-J scores differed across model types
- Mann-Whitney U tests for differences from methodology adjustments between RQ1/RQ2/RQ3
- Cliff's delta for the previous U tests (not in most recent paper draft, but will be added)
