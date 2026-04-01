import json
import os

MIN_YEAR = 2019

def process_files(base_dir):
    rows = []
    for (root, dirs, files) in os.walk(base_dir):
        for file in files:
            if file.endswith(".json"):
                path = os.path.join(root, file)
                components = path.split(os.sep)
                
                if len(components) < 2:
                    continue
                if not components[1].isdigit():
                    continue
                
                year = int(components[1])
                if year >= MIN_YEAR:
                    process_file(path, rows)

    print("id,exploitation,automatable,technical_impact")
    rows.sort(key=get_key)
    for row in rows:
        print(",".join(row))


def get_key(row):
    components = row[0].split("-")
    return int(components[1]), int(components[2])


def process_file(path, rows):
    #print(path)
    with open(path, "r") as f:
        data = json.load(f)

    if "containers" not in data or "adp" not in data["containers"]:
        return

    for container in data["containers"]["adp"]:
        if "title" in container and container["title"] == "CISA ADP Vulnrichment" and "metrics" in container:
            for metric in container["metrics"]:
                if "other" in metric and metric["other"]["type"] == "ssvc":
                    extract_metrics(metric, rows)

def extract_metrics(metric, rows):
    options = {}
    for option in metric["other"]["content"]["options"]:
        options.update(option)

    metric_id = metric["other"]["content"]["id"]
    exploitation = options["Exploitation"]
    automatable = options["Automatable"]
    technical_impact = options["Technical Impact"]

    rows.append((metric_id, exploitation, automatable, technical_impact))


if __name__ == "__main__":
    process_files("vulnrichment")
