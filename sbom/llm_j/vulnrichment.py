import json
import os

import requests
from requests.exceptions import RequestException


def get_vulnrichment_data(cve_id: str) -> dict:
    directory = os.getenv("VULNRICHMENT_DIR")

    if directory is None:
        return fetch_online_vulnrichment_data(cve_id)

    return load_vulnrichment_data_from_dir(cve_id, directory)


def fetch_online_vulnrichment_data(cve_id: str) -> dict:
    """
    Fetch CVE data from CISA's Vulnrichment repository.
    The repo uses CVE JSON 5.0 directory structure.
    """
    url = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/" + get_vulnrichment_path(cve_id)

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Not found in Vulnrichment database"}
        else:
            return {"error": "HTTP {}".format(response.status_code)}
    except RequestException as e:
        return {"error": str(e)}


def load_vulnrichment_data_from_dir(cve_id: str, directory: str) -> dict:
    item_path = get_vulnrichment_path(cve_id)
    full_path = os.path.join(directory, item_path)

    if os.path.isfile(full_path):
        with open(full_path, "r") as in_file:
            return json.load(in_file)

    return {"error": "Not found in Vulnrichment database"}


def get_vulnrichment_path(cve_id: str) -> str:
    parts = cve_id.split('-')
    if len(parts) != 3:
        return None

    year = parts[1]
    number = parts[2]

    # Calculate the thousand grouping (e.g., 1234 -> 1xxx, 12345 -> 12xxx)
    if len(number) < 4:
        number = number.zfill(4)

    group = number[:-3] + 'xxx'

    return "{}/{}/{}.json".format(year, group, cve_id)
