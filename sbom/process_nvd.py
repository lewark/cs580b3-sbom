import gzip
import json
import os
import sys

CVSS_PROPS = ["baseScore", "baseSeverity", "attackVector", "attackComplexity", "privilegesRequired", "userInteraction", "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact"]


def get_key(row):
    components = row[0].split("-")
    return int(components[1]), int(components[2])


def process_file(path):
    rows = []

    with gzip.open(path, "r") as f:
        data = json.load(f)

    for vuln in data["vulnerabilities"]:
        process_vuln(vuln, rows)

    print("id,published,lastModified,vulnStatus,description," + ",".join(CVSS_PROPS))
    rows.sort(key=get_key)
    for row in rows:
        print(",".join(row))


def process_vuln(vuln, rows):
    cve = vuln["cve"]
    cve_id = cve["id"]
    published = cve["published"]
    last_modified = cve["lastModified"]
    status = cve["vulnStatus"]

    description = ""
    for desc_item in cve["descriptions"]:
        if desc_item["lang"] == "en":
            description = desc_item["value"]

    if "cvssMetricV31" in cve["metrics"]:
        best_metric = None
        for metric in cve["metrics"]["cvssMetricV31"]:
            if best_metric is not None:
                if metric["type"] != "Primary":
                    continue

            best_metric = metric
            if metric["type"] == "Primary":
                break

        cvss_metrics = [str(best_metric["cvssData"].get(label, "")) for label in CVSS_PROPS]

        rows.append((cve_id, published, last_modified, json.dumps(status), json.dumps(description.replace('"', "'")), *cvss_metrics))


if __name__ == "__main__":
    process_file(sys.argv[1])
