import gzip
import json
import os
import time
from typing import Optional

import requests


NVD_REQUEST_DELAY = 1


loaded_years: set[str] = set()
vulns: dict[str, dict] = {}

def get_nvd_data(cve_id: str) -> dict:
    if cve_id in vulns:
        return vulns[cve_id]

    directory = os.getenv("NVD_DIR")
    key = os.getenv("NVD_API_KEY")

    if directory is not None:
        year = get_year(cve_id)
        load_cve_year(year)

        if cve_id in vulns:
            return vulns[cve_id]
    elif key is not None:
        return request_cve(key, cve_id)

    raise ValueError("Either the NVD_DIR or NVD_API_KEY environment variable must be specified to load NVD data")


def get_year(cve_id: str) -> Optional[str]:
    parts = cve_id.split('-')
    if len(parts) != 3:
        return None

    return parts[1]


def load_cve_year(year: Optional[str]) -> None:
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


def request_cve(key: str, cve_id: str) -> dict:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id

    # Based on https://github.com/vehemont/nvdlib/blob/main/nvdlib/cve.py
    # and https://nvd.nist.gov/developers/start-here
    headers = {"content-type": "application/json", "apiKey": key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        time.sleep(NVD_REQUEST_DELAY)

        vuln = None
        if response.status_code == 200:
            data = response.json()
            if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                vuln = data["vulnerabilities"][0]

            if isinstance(vuln, dict):
                vulns[cve_id] = vuln

        if vuln is None:
            return {"error": "Not found in Vulnrichment database"}
        else:
            return vuln
    except requests.RequestException as e:
        return {"error": str(e)}
