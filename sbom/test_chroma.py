import chromadb
client = chromadb.HttpClient(host="localhost", port=8000)
nvd = client.get_collection("nvd")
print(nvd.get("CVE-2002-0367"))
