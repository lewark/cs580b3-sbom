import json
import numpy
import os
import re
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

pattern = re.compile(r"llm-j-parsed_([a-z0-9\._\-]+)_(\d{4}-\d{2}-\d{2}_\d{6})\.json")


def get_model_scores(directory: str):
    scores: dict[str, list[float]] = {}

    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            if not filename.endswith(".json"):
                continue

            match = pattern.match(filename)

            if match is None:
                continue
            model_name = match.group(1)

            if model_name not in scores:
                scores[model_name] = []
            model_scores = scores[model_name]

            file_path = os.path.join(dirpath, filename)
            with open(file_path, 'r') as f:
                data = json.load(f)

            for item in data:
                score = item["llmj_analysis"]["score"]
                model_scores.append(score)

    return scores


def get_mean_sd(model_scores: dict[str, list[float]]) -> pd.DataFrame:
    model_names = sorted(model_scores.keys())
    rows = []
    for name in model_names:
        scores = model_scores[name]
        rows.append([
            name,
            np.mean(scores),
            np.std(scores),
            len(scores)
        ])

    return pd.DataFrame(rows, columns=["model", "mean", "sd", "count"])


def plot_model_scores(model_scores: dict[str, list[float]]) -> None:
    names = sorted(model_scores.keys())
    scores = [model_scores[name] for name in names]
    make_figure()
    plt.boxplot(scores, orientation="horizontal", tick_labels=names)
    plt.xlabel("LLM-J score")
    plt.savefig("model_scores.pdf")
    plt.savefig("model_scores.png")


def plot_model_bar(model_stats: pd.DataFrame) -> None:
    make_figure()

    y = np.arange(len(model_stats))

    plt.barh(y, model_stats["mean"], tick_label=model_stats["model"])
    plt.xlabel("Mean LLM-J score")
    plt.savefig("model_scores_bar.pdf")
    plt.savefig("model_scores_bar.png")

    make_figure()

    plt.barh(y, model_stats["count"], tick_label=model_stats["model"])
    plt.xlabel("Total reported vulnerabilities")
    plt.savefig("model_scores_count.pdf")
    plt.savefig("model_scores_count.png")


def make_figure():
    plt.figure(figsize=(5, 3), layout="constrained")


def main():
    if len(sys.argv) < 2:
        print("Please enter a directory name")
    dir_name = sys.argv[1]

    model_scores = get_model_scores(dir_name)
    model_df = get_mean_sd(model_scores)
    print(model_df)

    plot_model_bar(model_df)

    plot_model_scores(model_scores)


if __name__ == "__main__":
    main()
