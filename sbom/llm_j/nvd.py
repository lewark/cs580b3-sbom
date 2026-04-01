import gzip
import json
import os

loaded_years: set[str] = set()
vulns: dict[str, dict] = {}

def get_nvd_data(cve_id: str) -> dict:
    year = get_year(cve_id)
    load_cve_year(year)

    if cve_id in vulns:
        return vulns[cve_id]

    return {"error": "Not found in NVD database"}


def get_year(cve_id: str) -> str:
    parts = cve_id.split('-')
    if len(parts) != 3:
        return None

    return parts[1]


def load_cve_year(year: str):
    if (year is None) or (year in loaded_years):
        return

    directory = os.environ["NVD_DIR"]
    filename = "nvdcve-2.0-{}.json.gz".format(year)
    path = os.path.join(directory, filename)

    if not os.path.isfile(path):
        return

    with gzip.open(path, "r") as f:
        data = json.load(f)

    if "vulnerabilities" not in data:
        return

    for vuln in data["vulnerabilities"]:
        vulns[vuln["cve"]["id"]] = vuln
