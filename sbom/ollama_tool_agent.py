import json
import os
import sys
import shlex
import subprocess
import time
import chromadb
from chromadb.api.types import GetResult
from langchain_core.tools import tool
import ollama
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import create_agent
from langchain_community.document_loaders import JSONLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter, RecursiveJsonSplitter
from langchain_chroma import Chroma

MANUAL_APPROVE_COMMANDS = False


chroma_client = None


@tool
def run_command(command: str) -> str:
    """Execute a shell command in the current directory.
    Use this to explore the file system, find dependencies, or manually execute SBOM generation tools (e.g. syft or trivy).
    """
    print(f"\n[Tool Execution] Running command: {command}")

    if MANUAL_APPROVE_COMMANDS:
        if input(f"Execute '{command}'? (Y/N): ").lower() != "y":
            return "Command disallowed by user"

    split = shlex.split(command)
    if not split:
        return "Empty command"

    if split[0] == "cd":
        target_dir = split[1] if len(split) > 1 else os.environ.get("HOME", "/")
        if os.path.isdir(target_dir):
            os.chdir(target_dir)
            return f"Changed directory to {os.getcwd()}"
        else:
            return f"cd: {target_dir}: No such file or directory"

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, encoding="utf-8", timeout=120)
        output = result.stdout[:4000] # Truncate to prevent context overflow
        return output if output else "Command executed successfully with no output."
    except Exception as e:
        return f"Error executing command: {str(e)}"

@tool
def query_sbom_rag(query: str, sbom_file_path: str) -> str:
    """Use this to perform a RAG (Retrieval-Augmented Generation) search on a generated SBOM file.
    Give it a natural language query and the path to an SBOM (like a syft json file) to retrieve relevant components or vulnerabilities.
    """
    print(f"\n[Tool Execution] Querying SBOM '{sbom_file_path}' for: {query}")

    if not os.path.exists(sbom_file_path):
        return f"Error: SBOM file {sbom_file_path} does not exist. You may need to generate it first using 'run_command'."

    try:
        # Load the content of the file
        if sbom_file_path.endswith(".json"):
            # loader = JSONLoader(file_path=sbom_file_path, jq_schema=".", text_content=False)
            with open(sbom_file_path, "r") as in_file:
                json_data = json.load(in_file)
            text_splitter = RecursiveJsonSplitter(max_chunk_size=1000)

            # Chunk the SBOM data
            splits = text_splitter.create_documents(json_data)

        else:
            with open(sbom_file_path, "r") as in_file:
                data = in_file.read()
            # loader = TextLoader(sbom_file_path)
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
            # Chunk the SBOM data
            splits = text_splitter.create_documents([data])

        # docs = loader.load()

        # Use an Ollama embedding model locally
        # Note: 'nomic-embed-text' must be pulled in Ollama (ollama pull nomic-embed-text)
        embeddings = OllamaEmbeddings(
            model="nomic-embed-text",
            base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434")
        )

        # Embed and index into an ephemeral Chroma DB
        vectorstore = Chroma.from_documents(documents=splits, embedding=embeddings)
        retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

        results = retriever.invoke(query)
        context = "\n\n".join(doc.page_content for doc in results)

        # Cleanup vectorstore
        vectorstore.delete_collection()

        return f"Relevant SBOM Excerpts:\n{context}"

    except Exception as e:
        return f"Error reading or embedding SBOM: {str(e)}"


@tool
def list_sbom_vulnerabilities(sbom_file_path: str) -> str:
    """
    Query an SBOM file to produce a list of vulnerabilities affecting a project.
    """

    try:
        with open(sbom_file_path, "r") as f:
            data = json.load(f)

        vulns = []
        for entry in data["vulnerabilities"]:
            vuln = {
                "id": entry["id"]
            }

            if "description" in entry:
                vuln["description"] = entry["description"]

            if "affects" in entry:
                vuln["affects"] = [item["ref"] for item in entry["affects"]]

            if "ratings" in entry:
                severity = None
                in_kev = None
                for rating in entry["ratings"]:
                    if rating["method"] == "CVSSv31":
                        severity = rating["score"]
                    elif "justification" in rating and rating["justification"] == "Listed in CISA KEV" and rating["score"] > 0:
                        in_kev = True

                if severity is not None:
                    vuln["cvss_v3.1"] = severity
                if in_kev is not None:
                    vuln["known_exploited"] = True

        return json.dumps(vulns, indent=2)

    except Exception as e:
        return "Error loading SBOM: " + str(e)


# Setup Web Search
@tool
def web_search(query: str) -> str:
    """
    Given a query, search for relevant pages on the Internet.

    Args:
      query: The query to search for
    """
    # TODO: we may need to truncate results for local models
    return json.dumps(ollama.web_search(query, max_results=3).model_dump())


@tool
def search_nvd(query: str) -> str:
    """
    Search the National Vulnerability Database for entries with descriptions
    similar to the specified search query.

    Args:
      query: The query to search for
    """
    print("Search NVD:", query, flush=True)

    if chroma_client is None:
        raise ValueError("chroma_client not initialized")

    result = chroma_client.get_collection("nvd").query(query_texts=query, n_results=3)

    if result["documents"] is None or result["metadatas"] is None:
        return f"NO results for query '{query}'"

    result_list = []
    for doc_ids, documents, metadatas in zip(result["ids"], result["documents"], result["metadatas"]):
        for doc_id, document, metadata in zip(doc_ids, documents, metadatas):
            item = {}
            item.update(metadata)
            item["description"] = document
            result_list.append(item)

    return json.dumps(result_list)


@tool
def lookup_vulnerability(cve_id: str) -> str:
    """
    Look up a vulnerability from the National Vulnerability Database
    using its CVE ID number.

    Args:
      cve_id: The vulnerability ID to retrieve (e.g. CVE-2021-44228)
    """

    print("Lookup vulnerability", cve_id, flush=True)

    if chroma_client is None:
        raise ValueError("chroma_client not initialized")

    result = chroma_client.get_collection("nvd").get(cve_id)

    if result is None:
        return f"CVE {cve_id} not found"

    results = chroma_results_to_json(result)

    return json.dumps(results)


def chroma_results_to_json(results: GetResult) -> list[dict]:
    items = []

    print(results, flush=True)

    if results["documents"] is None or results["metadatas"] is None:
        return []

    for doc_id, document, metadata in zip(results["ids"], results["documents"], results["metadatas"]):
        item = {}
        item.update(metadata)
        item["description"] = document
        items.append(item)

    return items


def main():
    if len(sys.argv) < 2:
        print("Usage: python ollama-tool-agent.py [--cot] MODEL", flush=True)
        sys.exit(1)

    use_cot = False
    if "--cot" in sys.argv:
        use_cot = True
        sys.argv.remove("--cot")

    if len(sys.argv) < 2:
        print("Usage: python ollama-tool-agent.py [--cot] MODEL", flush=True)
        sys.exit(1)

    model = sys.argv[1]
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    print(f"Initializing LangChain Agent with model: {model}", flush=True)

    # 1. Initialize the LLM with Ollama
    llm = ChatOllama(
        model=model,
        base_url=host,
        temperature=0
    )

    # 2. Define tools
    #tools = [run_command, web_search, query_sbom_rag]
    tools = [run_command, lookup_vulnerability, search_nvd, web_search]

    # 3. Define System Message
    system_message = """Analyze this project to identify vulnerabilities in any software dependencies.

IMPORTANT EFFICIENCY CONSTRAINTS:
1. Identify the EXACT version of the product/codebase you are looking at.
2. Structure your analysis around that specific version only.
3. DO NOT waste time evaluating, listing, or discussing vulnerabilities for other versions of the product. Only report vulnerabilities that are known to actively affect the specific version you found in the directory.
4. If a vulnerability list is provided as a file path, you MUST use the `query_sbom_rag` tool to retrieve the vulnerabilities from it.
5. Perform your SSVC triage on those specific vulnerabilities by researching them using the `web_search` tool.

Your final response MUST be a structured valid JSON object containing only the list of vulnerabilities found.
Each vulnerability must include 'dependency_name', 'vulnerability_id' (e.g. CVE-XXXX-XXXX), 'description', and an 'ssvc_decision' which must be exactly one of: "Track", "Track*", "Attend", or "Act".

CRITICAL INSTRUCTION: Output ONLY the raw JSON object. Do NOT wrap the JSON in markdown blocks (e.g., no ```json and no ```). Do NOT add ANY conversational text (e.g., "Here is the output") before or after the JSON.

Example output format:
{
  "vulnerabilities": [
    {
      "dependency_name": "tomcat-coyote",
      "vulnerability_id": "CVE-2024-34750",
      "description": "Apache Tomcat - Denial of Service",
      "ssvc_decision": "Act"
    }
  ]
}"""

    print(system_message, flush=True)

    # 4. Construct langchain agent
    agent_executor = create_agent(llm, tools, system_prompt=system_message)

    print("\nStarting Advanced Triage Analysis...", flush=True)
    try:
        # Check standard current directory for vulnerability files
        vuln_files = [f for f in os.listdir('.') if f.endswith('.json') and ('triage' in f or 'vuln' in f)]

        # Also check common path for vulnerabilities mapped into the container
        software_name = os.getenv("SOFTWARE_NAME")
        if software_name:
            known_vuln_path = f'/scripts/sbom/vulnerabilities/minimal_triage_{software_name}.json'
        else:
            known_vuln_path = '/scripts/sbom/vulnerabilities/minimal_triage_tomcat.json'

        target_file = None
        if vuln_files:
            target_file = os.path.abspath(vuln_files[0])
        elif os.path.exists(known_vuln_path):
            target_file = known_vuln_path

        if target_file:
#             user_prompt = f"""
# A JSON vulnerability file containing the dependencies and vulnerabilities has been located at:
# {target_file}

# Please perform your SSVC triage analysis on these vulnerabilities.
# You MUST use the `query_sbom_rag` tool to search through this file, retrieve the vulnerabilities, and extract the relevant dependency names, vulnerability IDs, and descriptions.
# You can use `web_search` to look up details about these specific CVE/GHSA IDs if more information is needed to make an accurate SSVC decision.
# Once analyzed, provide your final response ONLY as a raw JSON object. Produce NO markdown blocks, NO backticks, and NO conversational filler text around the JSON.
# """
            user_prompt = f"""
A JSON vulnerability file containing the dependencies and vulnerabilities has been located at:
{target_file}

Please perform your SSVC triage analysis on these vulnerabilities.
You must read the file using the `cat` command, through the `run_command` tool.
You can use the `lookup_vulnerability` tool to retrieve additional information about these specific CVEs if more information is needed to make an accurate SSVC decision.
Once analyzed, provide your final response ONLY as a raw JSON object. Produce NO markdown blocks, NO backticks, and NO conversational filler text around the JSON.
"""
        else:
            user_prompt = "Please perform a cursory, high-level analysis of the codebase in the current directory to identify vulnerabilities in major software dependencies. Take a quick glance using the run_command tool. Do not be overly thorough. Once you have finished your fast analysis, provide your final response ONLY as a raw JSON object. Produce NO markdown blocks, NO backticks, and NO conversational filler text around the JSON."

        if use_cot:
            user_prompt += "\nThink through this step-by-step."

        print(user_prompt, flush=True)

        response = agent_executor.invoke({"messages": [("user", user_prompt)]}) #, print_mode="messages")
        print("\n\nFinal Decision Output:\n=====================\n", flush=True)
        print(response["messages"][-1].content)

        # Save results to a log file
        out_dir = os.getenv("OUTPUT_DIRECTORY", "/data/logs")

        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        timestamp = time.strftime("%Y-%m-%d_%H%M%S")
        model_label = model.replace(":", "_")
        filename = os.path.join(out_dir, f"{model_label}_{timestamp}.json")

        entries = []
        for msg in response["messages"]:
            if hasattr(msg, "dict"):
                entries.append(msg.model_dump())
            else:
                entries.append(str(msg))

        with open(filename, "w") as out_file:
            json.dump(entries, out_file, indent=2)

    except Exception as e:
         print(f"Error during agent execution: {e}")

if __name__ == "__main__":
    print("Connecting to Chroma", flush=True)
    chroma_client = chromadb.HttpClient(host="localhost", port=8000)
    print("Connected", flush=True)
    main()
