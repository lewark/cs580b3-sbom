import gzip
import json
import os
import sys
from typing import Optional

CVSS_PROPS = ["baseScore", "baseSeverity", "attackVector", "attackComplexity", "privilegesRequired", "userInteraction", "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact"]


def get_key(row):
    components = row[0].split("-")
    return int(components[1]), int(components[2])


def process_file(path):
    rows = []

    with gzip.open(path, "r") as f:
        data = json.load(f)

    cols = ["id", "published", "lastModified", "vulnStatus", "description", *CVSS_PROPS]

    for vuln in data["vulnerabilities"]:
        result = process_vuln(vuln)

        result["status"] = json.dumps(result["status"])
        result["description"] = json.dumps(result["description"].replace('"', "'"))

        for label in CVSS_PROPS:
            result[label] = result[label]

        rows.append(tuple([
            result.get(col, "") for col in cols
        ]))


    print(",".join(cols))
    rows.sort(key=get_key)
    for row in rows:
        print(",".join(row))


def process_vuln(vuln) -> dict:
    cve = vuln["cve"]
    cve_id = cve["id"]
    published = cve["published"]
    last_modified = cve["lastModified"]
    status = cve["vulnStatus"]

    description = ""
    for desc_item in cve["descriptions"]:
        if desc_item["lang"] == "en":
            description = desc_item["value"]

    item = {
        "id": cve_id,
        "published": published,
        "lastModified": last_modified,
        "vulnStatus": status,
        "description": description,
    }

    if "cvssMetricV31" in cve["metrics"]:
        best_metric = None
        for metric in cve["metrics"]["cvssMetricV31"]:
            if best_metric is not None:
                if metric["type"] != "Primary":
                    continue

            best_metric = metric
            if metric["type"] == "Primary":
                break

        if best_metric is not None:
            cvss_metrics = {
                best_metric["cvssData"].get(label, None) for label in CVSS_PROPS
            }
            item.update(cvss_metrics)

    return item


if __name__ == "__main__":
    process_file(sys.argv[1])
