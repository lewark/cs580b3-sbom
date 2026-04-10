import glob
import gzip
import json
import os
import sys

import chromadb

from .process_nvd import process_vuln


CHROMA_PORT = 8000


def connect_db():
    return chromadb.HttpClient(host="localhost", port=8000)


def create_nvd_collection(path: str):
    client = connect_db()

    for collection in client.list_collections():
        if collection.name == "nvd":
            client.delete_collection("nvd")

    collection = client.create_collection(name="nvd")

    for filename in glob.glob(os.path.join(path, "*.json.gz")):
        with gzip.open(filename, "r") as f:
            data = json.load(f)

        ids = []
        documents = []
        metadatas = []

        for vuln in data["vulnerabilities"]:
            entry = process_vuln(vuln)

            metadata = dict(entry)
            del metadata["description"]

            ids.append(entry["id"])
            documents.append(entry["description"])
            metadatas.append(metadata)

        collection.add(ids=ids, documents=documents, metadatas=metadatas)


if __name__ == "__main__":
    create_nvd_collection(sys.argv[1])
