import os
import sys
import shlex
import subprocess
from langchain_core.tools import tool
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_community.document_loaders import JSONLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma

MANUAL_APPROVE_COMMANDS = False

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
             loader = JSONLoader(file_path=sbom_file_path, jq_schema=".", text_content=False)
        else:
             loader = TextLoader(sbom_file_path)
             
        docs = loader.load()
        
        # Chunk the SBOM data
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        splits = text_splitter.split_documents(docs)
        
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
web_search = DuckDuckGoSearchRun(
    name="web_search", 
    description="Search the web for up-to-date vulnerability databases, CVE details, NVD lookups, or exploit info."
)

def main():
    if len(sys.argv) < 2:
        print("Usage: python ollama-tool-agent.py MODEL")
        sys.exit(1)

    model = sys.argv[1]
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    print(f"Initializing LangChain Agent with model: {model}")

    # 1. Initialize the LLM with Ollama
    llm = ChatOllama(
        model=model,
        base_url=host,
        temperature=0
    )

    # 2. Define tools
    tools = [run_command] #, list_sbom_vulnerabilities] #, web_search]

    # 3. Create prompt template
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an expert security analysis assistant determining SSVC priority. You have tools available: "
                   "1. run_command: Run linux shell commands. Useful to list files, cat dependency files (e.g. package.json/pom.xml), or execute cli tools like syft. "
                   #"2. query_sbom_rag: RAG on a given SBOM file. "
                   #"2. list_sbom_vulnerabilities: List vulnerabilities contained in an SBOM file. "
                   #"3. web_search: Find latest CVE info on DuckDuckGo. "
                   "IMPORTANT EFFICIENCY CONSTRAINTS: Identify the exact version of the codebase you are in. Do not waste time evaluating or listing vulnerabilities for other versions. Focus strictly on vulnerabilities that affect the specific version you found. "
                   "Perform a CURSORY scan only—do not try to be overly thorough or read every single file. A quick glance at the top-level dependencies is perfectly sufficient. "
                   #"Gather your information quickly, identify main dependencies, look up vulnerabilities via web_search, and output a final decision."),
                   "Gather your information quickly, identify main dependencies, and output a final decision."),
        ("placeholder", "{chat_history}"),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    # 4. Construct tool-calling agent
    agent = create_tool_calling_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

    print("\nStarting Advanced Triage Analysis...")
    try:
        #response = agent_executor.invoke({"input": "Perform a cursory analysis of the codebase in the current directory. Take a quick glance to find main dependencies using the shell. For any key dependencies found, do a quick web search for known vulnerabilities and provide your final SSVC triage decision."})
        response = agent_executor.invoke({"input": "Perform a cursory analysis of the codebase in the current directory. Take a quick glance to find main dependencies using the shell. For any key dependencies found, identify known vulnerabilities and provide your final SSVC triage decision."})
        print("\n\nFinal Decision Output:\n=====================\n")
        print(response.get("output"))
    except Exception as e:
         print(f"Error during agent execution: {e}")

if __name__ == "__main__":
    main()
