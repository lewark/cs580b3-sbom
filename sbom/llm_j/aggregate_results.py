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


def get_statistics(model_scores: pd.DataFrame):
    model_names = sorted(model_scores.keys())
    rows = []

    items = model_scores.drop(columns="Variant").groupby(["Model", "Prompt mode", "Tool mode"]).agg(["mean", "std", "count"])
    print(items)
    # run Welch's one-way ANOVA test
    # F = scipy.stats.f_oneway(*items, equal_var=False)

    # make_figure()
    # sns.barplot(items, y="Model", x="count")

    # print(F)

    # for i, name in enumerate(model_names):
    #     scores = model_scores[name]
    #     rows.append([
    #         name,
    #         np.mean(scores),
    #         np.std(scores),
    #         len(scores),
    # ])

    return items



def plot_model_scores(model_scores: pd.DataFrame) -> None:
    make_figure()
    sns.boxplot(model_scores, y="Model", x="LLM-J Score", hue="Variant")
    plt.savefig("llmj_scores_all.pdf")
    plt.savefig("llmj_scores_all.png")


    make_figure()
    model_scores_rq1 = model_scores[model_scores["Variant"] == "standard-prompt/non-tooling"]
    sns.boxplot(model_scores_rq1, y="Model", x="LLM-J Score")
    plt.savefig("llmj_scores_rq1.pdf")
    plt.savefig("llmj_scores_rq1.png")

    make_figure()
    model_scores_rq2 = model_scores[model_scores["Variant"] == "standard-prompt/tooling"]
    sns.boxplot(model_scores_rq2, y="Model", x="LLM-J Score")
    plt.savefig("llmj_scores_rq2.pdf")
    plt.savefig("llmj_scores_rq2.png")

    make_figure()
    model_scores_rq3 = model_scores[model_scores["Prompt mode"] == "chain-of-thought-prompt"]
    sns.boxplot(model_scores_rq3, y="Model", x="LLM-J Score", hue="Tool mode")
    plt.savefig("llmj_scores_rq3.pdf")
    plt.savefig("llmj_scores_rq3.png")


def plot_model_bar(model_stats: pd.DataFrame) -> None:
    make_figure()

    y = np.arange(len(model_stats))

    make_figure()

    plt.barh(y, model_stats["count"], tick_label=model_stats["model"])
    plt.xlabel("Total reported vulnerabilities")
    plt.savefig("model_scores_count.pdf")
    plt.savefig("model_scores_count.png")


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

    plot_model_scores(model_scores)


if __name__ == "__main__":
    main()
