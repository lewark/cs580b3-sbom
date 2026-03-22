import os
import json
import re
import requests
import glob
from requests.exceptions import RequestException

LOG_DIR = 'logs'
OUTPUT_FILE = 'llmj_analysis_results.json'
OLLAMA_API_URL = 'http://localhost:11434/api/chat'
OLLAMA_MODEL = 'qwen3.5:397b-cloud'

def extract_cves(data):
    """Extract CVE IDs from the parsed JSON data, falling back to regex if needed."""
    cves = set()
    
    if isinstance(data, dict) and "vulnerabilities" in data:
        for vuln in data["vulnerabilities"]:
            if isinstance(vuln, dict) and "vulnerability_id" in vuln:
                cves.add(vuln["vulnerability_id"])
                
    if cves:
        return list(cves)
        
    text = data if isinstance(data, str) else json.dumps(data)
    pattern = r'CVE-\d{4}-\d{4,7}'
    return list(set(re.findall(pattern, text)))

def fetch_vulnrichment_data(cve_id):
    """
    Fetch CVE data from CISA's Vulnrichment repository.
    The repo uses CVE JSON 5.0 directory structure.
    """
    parts = cve_id.split('-')
    if len(parts) != 3:
        return None
    
    year = parts[1]
    number = parts[2]
    
    # Calculate the thousand grouping (e.g., 1234 -> 1xxx, 12345 -> 12xxx)
    if len(number) < 4:
        number = number.zfill(4)
        
    group = number[:-3] + 'xxx'
    
    url = f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{group}/{cve_id}.json"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Not found in Vulnrichment database"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except RequestException as e:
        return {"error": str(e)}

def analyze_with_llmj(cve_id, log_context, vuln_data):
    """
    Perform LLM-J (LLM-as-a-Judge) analysis using local Ollama model.
    """
    prompt = f"""
    You are an expert cybersecurity AI judge (LLM-J). You are evaluating the accuracy and quality of another LLM's vulnerability analysis against the ground truth database.
    
    CVE ID: {cve_id}
    
    Candidate LLM Analysis (to be evaluated):
    {json.dumps(log_context, indent=2)}
    
    Ground Truth (CISA Vulnrichment Data):
    {json.dumps(vuln_data, indent=2)}
    
    Evaluate how well the candidate LLM's analysis matches the ground truth. 
    Consider accuracy of the description, severity/impact, and any SSVC or action decisions provided.
    
    Please provide the following:
    1. Score: An integer score from 1 to 10, where 10 is a perfect match and 1 is completely inaccurate or hallucinated.
    2. Reasoning: A brief 1-2 sentence explanation of why this score was given, noting any missing or hallucinated information.
    3. Accuracy: A single word rating ("High", "Medium", or "Low").
    
    Provide the output in valid JSON format ONLY, with the keys: 
    "score", "reasoning", "accuracy".
    """
    
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are an expert security analyst and LLM judge. Output strictly valid JSON without markdown code blocks."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "format": "json",
        "stream": True
    }
    
    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=120, stream=True)
        response.raise_for_status()
        
        result_text = ""
        print("Model generated output: ", end="", flush=True)
        for line in response.iter_lines():
            if line:
                chunk = json.loads(line)
                content = chunk.get("message", {}).get("content", "")
                result_text += content
                print(content, end="", flush=True)
        print("\n")
        
        # Try to parse the JSON returned by the model
        try:
            return json.loads(result_text)
        except json.JSONDecodeError:
            # Fallback if the model didn't return perfect JSON
            return {"raw_output": result_text}
            
    except RequestException as e:
        print(f"Error communicating with Ollama for {cve_id}: {e}")
        return {"error": str(e)}

def main():
    if not os.path.exists(LOG_DIR):
        print(f"Directory {LOG_DIR} not found.")
        return

    log_files = glob.glob(os.path.join(LOG_DIR, '*.json'))
    print(f"Found {len(log_files)} log files. Beginning processing...")
    
    results = []

    for file_path in log_files:
        print(f"\nProcessing {file_path}...")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
        except Exception as e:
            print(f"Could not read {file_path}: {e}")
            continue

        cves = extract_cves(log_data)
        if not cves:
            print(f"No CVEs found in {file_path}.")
            continue
            
        print(f"Found CVEs: {', '.join(cves)}")
        
        for cve in cves:
            print(f"Fetching Vulnrichment data for {cve}...")
            vuln_data = fetch_vulnrichment_data(cve)
            
            # Narrow down log_context if it's structured
            cve_context = log_data
            if isinstance(log_data, dict) and "vulnerabilities" in log_data:
                cve_context = [v for v in log_data["vulnerabilities"] if v.get("vulnerability_id") == cve]
            
            print(f"Performing LLM-J analysis for {cve} with {OLLAMA_MODEL}...")
            analysis = analyze_with_llmj(cve, cve_context, vuln_data)
            
            result_entry = {
                "source_log": os.path.basename(file_path),
                "cve_id": cve,
                "vulnrichment_status": "Found" if "error" not in vuln_data else vuln_data["error"],
                "llmj_analysis": analysis
            }
            results.append(result_entry)

    # Save outputs
    print(f"\nSaving results to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
        
    print("Analysis complete!")

if __name__ == '__main__':
    main()
