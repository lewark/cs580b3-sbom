import json
import numpy
import os
import re
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import scipy.stats
from cliffs_delta import cliffs_delta

from sbom.paths import find_json_files, get_file_categories

pattern = re.compile(r"llm-j-parsed_([a-z0-9\._\-]+)_(\d{4}-\d{2}-\d{2}_\d{6})\.json")


def get_model_scores(directory: str) -> pd.DataFrame:
    rows = []

    for file_path in find_json_files(directory, required_dirs=["llm-j-analysis-logs"], excluded_dirs=["iteration4", "iteration5"]):
        if not file_path.endswith(".json"):
            continue

        filename = os.path.basename(file_path)

        match = pattern.match(filename)

        if match is None:
            continue
        model_name = match.group(1)

        with open(file_path, 'r') as f:
            data = json.load(f)

        prompt_mode, tool_mode = get_file_categories(file_path)

        for item in data:
            score = item["llmj_analysis"]["score"]
            variant = prompt_mode + "/" + tool_mode
            row = [model_name, prompt_mode, tool_mode, variant, score]
            rows.append(row)

    return pd.DataFrame(rows, columns=["Model", "Prompt mode", "Tool mode", "Variant", "LLM-J Score"])


LABELS = [
    ("rq1", ["standard-prompt", "non-tooling"]),
    ("rq2", ["standard-prompt", "tooling"]),
    ("rq3-non-tooling", ["chain-of-thought-prompt", "non-tooling"]),
    ("rq3-tooling", ["chain-of-thought-prompt", "tooling"])
]


def get_statistics(model_scores: pd.DataFrame):
    model_names = sorted(set(model_scores["Model"]))

    items = model_scores.drop(columns="Variant").groupby(["Model", "Prompt mode", "Tool mode"]).agg(["mean", "std", "count"])
    # print(items)

    rq1_values, rq2_values, rq3_non_tooling_values, rq3_tooling_values = {}, {}, {}, {}

    for rq, tags in LABELS:
        prompt_mode, tooling_mode = tags
        scores_by_model = get_scores_by_model(model_scores, model_names, prompt_mode, tooling_mode)

        # run Kruskal-Wallis test
        values = scores_by_model.values()
        F = scipy.stats.kruskal(*values)
        print(f"{rq}: H={F.statistic} p={F.pvalue}")

        if rq == "rq1":
            rq1_values = scores_by_model
        elif rq == "rq2":
            rq2_values = scores_by_model
        elif rq == "rq3-non-tooling":
            rq3_non_tooling_values = scores_by_model
        elif rq == "rq3-tooling":
            rq3_tooling_values = scores_by_model
    
    print("\nComparison of non-tooling (RQ1) and tooling (RQ2) models:")
    compare_model_llmj_values(rq1_values, rq2_values)

    print("\nComparison of tooling (RQ2) and tooling CoT (RQ3) models:")
    compare_model_llmj_values(rq2_values, rq3_tooling_values)

    return items


def check_pairwise_u(filtered_names: list[str], scores_by_model: dict[str, list[float]]):
    # Currently unused
    for i, model_name1 in enumerate(filtered_names):
        for j, model_name2 in enumerate(filtered_names):
            if j <= i:
                continue
            x = scores_by_model[model_name1]
            y = scores_by_model[model_name2]
            res = scipy.stats.mannwhitneyu(x, y)
            if res.pvalue <= 0.05:
                print(model_name1, model_name2, res)


def get_scores_by_model(
    model_scores: pd.DataFrame,
    model_names: list[str],
    prompt_mode: str,
    tooling_mode: str
) -> dict[str, list[float]]:

    variant = prompt_mode + "/" + tooling_mode
    scores_filtered = model_scores[model_scores["Variant"] == variant]

    scores_by_model: dict[str, list[float]] = {}
    for model_name in model_names:
        model_series = scores_filtered[scores_filtered["Model"] == model_name]["LLM-J Score"]
        if len(model_series) > 0:
            scores_by_model[model_name] = list(model_series)

    return scores_by_model


def compare_model_llmj_values(values_a, values_b):
    joined_names = sorted(
        set(values_a.keys())
        .intersection(
            set(values_b.keys())
        )
    )
    for model_name in joined_names:
        x = values_a[model_name]
        y = values_b[model_name]
        result = scipy.stats.mannwhitneyu(x, y)
        d, res = cliffs_delta(x, y)
        print(f"{model_name}: median(x)={np.median(x)} median(y)={np.median(y)} U={result.statistic} p={result.pvalue} cliffs_delta={d} {res}")


def plot_model_scores(model_scores: pd.DataFrame) -> None:
    make_figure()
    sns.boxplot(model_scores, y="Model", x="LLM-J Score", hue="Variant")
    plt.savefig("figures/llmj_scores_all.pdf")
    plt.savefig("figures/llmj_scores_all.png")

    make_figure()
    model_scores_rq1 = model_scores[model_scores["Variant"] == "standard-prompt/non-tooling"]
    sns.boxplot(model_scores_rq1, y="Model", x="LLM-J Score")
    plt.savefig("figures/llmj_scores_rq1.pdf")
    plt.savefig("figures/llmj_scores_rq1.png")

    make_figure()
    model_counts_rq1 = model_scores_rq1.assign(Count=1).groupby("Model").agg("count")
    # print(model_counts_rq1)
    sns.barplot(model_counts_rq1, y="Model", x="Count")
    plt.savefig("figures/vuln_counts_rq1.pdf")
    plt.savefig("figures/vuln_counts_rq1.png")

    make_figure()
    model_scores_rq2 = model_scores[model_scores["Variant"] == "standard-prompt/tooling"]
    sns.boxplot(model_scores_rq2, y="Model", x="LLM-J Score")
    plt.savefig("figures/llmj_scores_rq2.pdf")
    plt.savefig("figures/llmj_scores_rq2.png")

    make_figure()
    model_counts_rq2 = model_scores_rq2.assign(Count=1).groupby("Model").agg("count")
    # print(model_counts_rq2)
    sns.barplot(model_counts_rq2, y="Model", x="Count")
    plt.savefig("figures/vuln_counts_rq2.pdf")
    plt.savefig("figures/vuln_counts_rq2.png")

    make_figure()
    model_scores_rq3 = model_scores[model_scores["Prompt mode"] == "chain-of-thought-prompt"]
    sns.boxplot(model_scores_rq3, y="Model", x="LLM-J Score", hue="Tool mode")
    plt.savefig("figures/llmj_scores_rq3.pdf")
    plt.savefig("figures/llmj_scores_rq3.png")

    make_figure()
    model_counts_rq3 = model_scores_rq3.assign(Count=1).groupby(["Model", "Tool mode"]).agg("count")
    # print(model_counts_rq3)
    sns.barplot(model_counts_rq3, y="Model", x="Count", hue="Tool mode")
    plt.savefig("figures/vuln_counts_rq3.pdf")
    plt.savefig("figures/vuln_counts_rq3.png")


def plot_model_bar(model_stats: pd.DataFrame) -> None:
    make_figure()

    y = np.arange(len(model_stats))

    make_figure()

    plt.barh(y, model_stats["count"], tick_label=model_stats["model"])
    plt.xlabel("Total reported vulnerabilities")
    plt.savefig("figures/model_scores_count.pdf")
    plt.savefig("figures/model_scores_count.png")


def make_figure():
    plt.figure(figsize=(5 * 1, 3 * 1), layout="constrained")


def main():
    if len(sys.argv) < 2:
        print("Please enter a directory name")
    dir_name = sys.argv[1]

    model_scores = get_model_scores(dir_name)
    get_statistics(model_scores)
    # print(model_df)

    # plot_model_bar(model_df)

    if not os.path.isdir("figures"):
        os.mkdir("figures")

    plot_model_scores(model_scores)
    print("\nWrote figures to 'figures' directory")


if __name__ == "__main__":
    main()
