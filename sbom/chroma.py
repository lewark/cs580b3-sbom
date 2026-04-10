import gzip
import json
import sys

import chromadb

from .process_nvd import process_vuln


CHROMA_PORT = 8000


def connect_db():
    return chromadb.HttpClient(host="localhost", port=8000)


def create_nvd_collection(path: str):
    client = connect_db()

    collection = client.create_collection(name="nvd")

    with gzip.open(path, "r") as f:
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
