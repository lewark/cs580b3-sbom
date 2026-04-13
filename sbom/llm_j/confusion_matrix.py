import json
import numpy
import os
import re
import sys

import matplotlib.pyplot as plt
import numpy as np
import numpy.typing as npt
import pandas as pd

from sbom.paths import find_json_files

from .vulnrichment import get_vulnrichment_data

pattern = re.compile(r"^parsed_([a-z0-9\._\-]+)_(\d{4}-\d{2}-\d{2}_\d{6})\.json")

LABELS = ["Track", "Track*", "Attend", "Act"]
INDEXES = { text: i for i, text in enumerate(LABELS) }
MISSION_WELL_BEING = "medium"


def get_confusion_matrices(directory: str) -> dict[str, npt.NDArray]:
    confusion_matrices = {}

    decision_tree = load_decision_tree()

    for file_path in find_json_files(directory, required_strs=["parsed-logs"], excluded_strs=["llm-j-analysis-logs", "iteration4", "iteration5"]):
        filename = os.path.basename(file_path)
        if not filename.endswith(".json"):
            continue

        match = pattern.match(filename)

        if match is None:
            continue
        model_name = match.group(1)

        with open(file_path, 'r') as f:
            data = json.load(f)

        if "vulnerabilities" not in data:
            continue

        if model_name not in confusion_matrices:
            confusion_matrices[model_name] = np.zeros((5, 4))
        confusion_matrix = confusion_matrices[model_name]

        for item in data["vulnerabilities"]:
            vuln_id = item["vulnerability_id"]
            predicted_decision = item["ssvc_decision"]

            result = get_vulnrichment_ssvc(vuln_id)
            if result is None:
                confusion_matrix[4, INDEXES[predicted_decision]] += 1
                continue
            actual_decision = get_decision(decision_tree, result, MISSION_WELL_BEING)

            confusion_matrix[INDEXES[actual_decision], INDEXES[predicted_decision]] += 1

    return confusion_matrices


def load_decision_tree() -> dict:
    table = pd.read_csv("ssvc_decision_tree.csv")
    items = {}

    for row in table.iloc:
        print(row)
        key = tuple([row[x] for x in ["Exploitation", "Automatable", "Technical Impact", "Mission and Well-being"]])
        value = row["Decision"]

        items[key] = value

    return items


def get_decision(decision_tree: dict, result: dict, mission_well_being: str):
    options = {}
    for opt in result["options"]:
        options.update(opt)

    key = (options["Exploitation"], options["Automatable"], options["Technical Impact"], mission_well_being)
    return decision_tree[key]


def get_vulnrichment_ssvc(vuln_id: str):
    data = get_vulnrichment_data(vuln_id)

    if ("containers" not in data) or ("adp" not in data["containers"]):
        return None

    ssvc = None
    for entry in data["containers"]["adp"]:
        if (entry["title"] != "CISA ADP Vulnrichment") or ("metrics" not in entry):
            continue

        for metric in entry["metrics"]:
            if ("other" not in metric) or ("type" not in metric["other"]) or (metric["other"]["type"] != "ssvc"):
                continue

            ssvc = metric["other"]["content"]
            break

        if ssvc is not None:
            break

    return ssvc


def make_figure():
    plt.figure(figsize=(4, 3), layout="constrained")


def plot_confusion_matrix(confusion_matrix: npt.NDArray, label: str):
    make_figure()

    midrange = (np.min(confusion_matrix) + np.max(confusion_matrix)) / 2

    print(confusion_matrix)
    plt.imshow(confusion_matrix)
    for row in range(confusion_matrix.shape[0]):
        for col in range(confusion_matrix.shape[1]):
            item = int(confusion_matrix[row, col])
            color = "black" if item >= midrange else "white"
            plt.text(col, row, str(item), ha="center", va="center", color=color)

    plt.colorbar()
    plt.xlabel("Predicted decision")
    plt.ylabel("Correct decision")
    plt.xticks(np.arange(4), LABELS)
    plt.yticks(np.arange(5), LABELS + ["Not listed"])

    plt.savefig(f"confusion_matrix_{label}.pdf")
    plt.savefig(f"confusion_matrix_{label}.png")


def main():
    if len(sys.argv) < 2:
        print("Please enter a directory name")
    dir_name = sys.argv[1]

    confusion_matrices = get_confusion_matrices(dir_name)

    for model_name, confusion_matrix in confusion_matrices.items():
        plot_confusion_matrix(confusion_matrix, model_name)


if __name__ == "__main__":
    main()
