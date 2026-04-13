from collections.abc import Iterable
import json
from typing import Optional
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


def get_confusion_matrices(
    directory: str,
    required_dirs: list[str],
    required_strs: list[str],
    mission_well_being: str
) -> tuple[dict[str, npt.NDArray], dict[str, npt.NDArray]]:
    confusion_matrices = {}
    confusion_matrices_2 = {}

    decision_tree = load_decision_tree()

    sboms = load_sboms()

    for file_path in find_json_files(
        directory, required_dirs=["parsed-logs"] + required_dirs,
        excluded_dirs=["llm-j-analysis-logs", "iteration4", "iteration5"]
    ):
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
            confusion_matrices[model_name] = np.zeros((5, 5))
            confusion_matrices_2[model_name] = np.zeros((2, 2))
        confusion_matrix = confusion_matrices[model_name]

        project_name = get_relevant_project(sboms.keys(), file_path)
        assert project_name is not None

        actual_vulns = sboms[project_name]
        predicted_vulns = set([item["vulnerability_id"] for item in data["vulnerabilities"]])

        tp = len(actual_vulns.intersection(predicted_vulns))
        fp = len(predicted_vulns.difference(actual_vulns))
        tn = 0
        fn = len(actual_vulns.difference(predicted_vulns))
        mat2 = confusion_matrices_2[model_name]
        mat2 += np.array([
            [tp, fn],
            [fp, tn]
        ])

        for item in data["vulnerabilities"]:
            vuln_id = item["vulnerability_id"]
            predicted_decision = item["ssvc_decision"]

            result = get_vulnrichment_ssvc(vuln_id)

            if result is None:
                confusion_matrix[4, INDEXES[predicted_decision]] += 1
            else:
                actual_decision = get_decision(decision_tree, result, mission_well_being)
                confusion_matrix[INDEXES[actual_decision], INDEXES.get(predicted_decision, 4)] += 1

    return confusion_matrices, confusion_matrices_2


def get_metrics_df(confusion_matrices_2: dict[str, npt.NDArray]) -> pd.DataFrame:
    metrics_rows = []

    for model_name, mat in confusion_matrices_2.items():
        tp = mat[0,0]
        fn = mat[0,1]
        fp = mat[1,0]

        # actual_count = tp + fn
        # predicted_count = tp + fp

        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1 = 2 * tp / ((2 * tp) + fp + fn)

        metrics_rows.append((model_name, precision, recall, f1))

    return pd.DataFrame(metrics_rows, columns=["Model", "Precision", "Recall", "F1"])


def load_sboms() -> dict[str, set[str]]:
    entries = {}

    sbom_dir = "sbom/vulnerabilities"

    pattern = re.compile(r"^minimal_triage_(\w+)\.json$")
    for file in os.listdir(sbom_dir):
        match = pattern.match(file)

        if not match:
            continue

        project_name = match.group(1)

        with open(os.path.join(sbom_dir, file)) as in_file:
            vulns = json.load(in_file)

        entries[project_name] = set([vuln["related_cves"] for vuln in vulns])

    return entries


def get_relevant_project(projects: Iterable[str], path: str) -> Optional[str]:
    components = path.split(os.sep)
    for project in projects:
        if project in components:
            return project
    return None


def load_decision_tree() -> dict:
    table = pd.read_csv("ssvc_decision_tree.csv")
    items = {}

    for row in table.iloc:
        # print(row)
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
    plt.figure(figsize=(4.25, 3), layout="constrained")


def plot_confusion_matrix(confusion_matrix: npt.NDArray, label: str):
    make_figure()

    # print(confusion_matrix)
    draw_grid(confusion_matrix)

    plt.xlabel("Predicted decision")
    plt.ylabel("Correct decision")
    plt.xticks(np.arange(5), LABELS + ["Other"])
    plt.yticks(np.arange(5), LABELS + ["Not listed"])

    plt.savefig(f"confusion_matrix_{label}.pdf")
    plt.savefig(f"confusion_matrix_{label}.png")


def draw_grid(confusion_matrix: npt.NDArray):
    midrange = (np.min(confusion_matrix) + np.max(confusion_matrix)) / 2
    plt.imshow(confusion_matrix)
    for row in range(confusion_matrix.shape[0]):
        for col in range(confusion_matrix.shape[1]):
            item = int(confusion_matrix[row, col])
            color = "black" if item >= midrange else "white"
            plt.text(col, row, str(item), ha="center", va="center", color=color)

    plt.colorbar()


def plot_2x2_confusion_matrix(confusion_matrix: npt.NDArray, label: str):
    make_figure()

    # print(confusion_matrix)
    draw_grid(confusion_matrix)

    plt.xlabel("Predicted decision")
    plt.ylabel("Correct decision")
    labels = ["Present", "Not present"]
    plt.xticks(np.arange(2), labels)
    plt.yticks(np.arange(2), labels)

    plt.savefig(f"confusion_matrix_{label}_binary.pdf")
    plt.savefig(f"confusion_matrix_{label}_binary.png")


def main():
    if len(sys.argv) < 2:
        print("Please enter a directory name")
    dir_name = sys.argv[1]

    labels = [
        ("rq1", ["standard-prompt", "non-tooling"]),
        ("rq2", ["standard-prompt", "tooling"]),
        ("rq3-non-tooling", ["chain-of-thought-prompt", "non-tooling"]),
        ("rq3-tooling", ["chain-of-thought-prompt", "tooling"])
    ]

    for label, required_dirs in labels:
        print(label)

        confusion_matrices, confusion_matrices_2 = get_confusion_matrices(dir_name, required_dirs, [], MISSION_WELL_BEING)

        metrics_df = get_metrics_df(confusion_matrices_2)
        print(metrics_df)

        if label in ["rq1", "rq2"]:
            target_model = "glm-5.1_cloud"
            for mission_well_being in ["low", "medium", "high"]:
                confusion_matrices, confusion_matrices_2 = get_confusion_matrices(dir_name, required_dirs, [target_model], mission_well_being)
                plot_confusion_matrix(confusion_matrices[target_model], f"{label}-{mission_well_being}-{target_model}")
                # plot_2x2_confusion_matrix(confusion_matrices_2[target_model], label + "-" + target_model)

        # for model_name, confusion_matrix in confusion_matrices.items():
        #     plot_confusion_matrix(confusion_matrix, model_name)

        # for model_name, confusion_matrix in confusion_matrices_2.items():
        #     plot_2x2_confusion_matrix(confusion_matrix, model_name)


if __name__ == "__main__":
    main()
