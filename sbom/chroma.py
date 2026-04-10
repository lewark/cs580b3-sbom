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


def create_nvd_collection(path: str):
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

    for filename in glob.glob(os.path.join(path, "*.json.gz")):
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

            ids.append(entry["id"])
            documents.append(entry["description"])
            metadatas.append(metadata)

        for i in tqdm(range(0, len(ids), CHUNK_SIZE)):
            collection.add(
                ids=ids[i:i+CHUNK_SIZE],
                documents=documents[i:i+CHUNK_SIZE],
                metadatas=metadatas[i:i+CHUNK_SIZE]
            )


if __name__ == "__main__":
    create_nvd_collection(sys.argv[1])
