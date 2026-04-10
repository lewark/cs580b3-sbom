import argparse
import glob
import gzip
import json
import os
import sys

import chromadb
from tqdm import tqdm

from .process_nvd import process_vuln


CHROMA_PORT = 8000


def connect_db():
    return chromadb.HttpClient(host="localhost", port=8000)


def create_nvd_collection(nvd_directory: str, kev_file: str):
    client = connect_db()

    for collection in client.list_collections():
        if collection.name == "nvd":
            if input("Delete existing NVD collection?").lower().startswith("y"):
                client.delete_collection("nvd")
            else:
                print("Exiting.")
                sys.exit(1)

    collection = client.create_collection(name="nvd")

    CHUNK_SIZE = 1000

    with open(kev_file, "r") as kev_reader:
        kev_data = json.load(kev_reader)

    kev_vulns: dict[str, dict] = {}
    for item in kev_data["vulnerabilities"]:
        kev_vulns[item["cveID"]] = item

    for filename in sorted(glob.glob(os.path.join(nvd_directory, "*.json.gz"))):
        print("Ingesting", filename)

        with gzip.open(filename, "r") as f:
            data = json.load(f)

        ids = []
        documents = []
        metadatas = []

        for vuln in data["vulnerabilities"]:
            entry = process_vuln(vuln)

            metadata = dict(entry)
            del metadata["description"]

            cve_id = entry["id"]
            kev_entry = kev_vulns.get(cve_id)

            if kev_entry is None:
                metadata["knownExploitedVulnerability"] = False

            else:
                metadata["knownExploitedVulnerability"] = True
                mapping = {
                    "vendorProject": "kevVendorProject", "product": "kevProduct", "vulnerabilityName": "kevVulnerabilityName", "dateAdded": "kevDateAdded",
                    "shortDescription": "kevShortDescription", "requiredAction": "kevRequiredAction", "dueDate": "kevDueDate", "knownRansomwareCampaignUse": "kevKnownRansomwareCampaignUse"
                }

                for src_attr, dest_attr in mapping.items():
                    metadata[dest_attr] = kev_entry[src_attr]

            ids.append(cve_id)
            documents.append(entry["description"])
            metadatas.append(metadata)

        for i in tqdm(range(0, len(ids), CHUNK_SIZE)):
            collection.add(
                ids=ids[i:i+CHUNK_SIZE],
                documents=documents[i:i+CHUNK_SIZE],
                metadatas=metadatas[i:i+CHUNK_SIZE]
            )

        break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("nvd_directory")
    parser.add_argument("kev_file")
    args = parser.parse_args()

    create_nvd_collection(args.nvd_directory, args.kev_file)
