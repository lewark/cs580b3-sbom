import os
import json
import re
import requests
import glob

from requests.exceptions import RequestException

from .vulnrichment import get_vulnrichment_data


LOG_DIR = '../logs/parsed-logs'
OUTPUT_DIR = '../logs/llm-j-analysis-logs'
OLLAMA_API_URL = 'http://localhost:11434/api/chat'
OLLAMA_MODEL = 'gpt-oss:120b-cloud'

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


def analyze_with_llmj(cve_id, log_context, vuln_data):
    """
    Perform LLM-J (LLM-as-a-Judge) analysis using local Ollama model.
    """
    prompt = """
    You are an expert cybersecurity AI judge (LLM-J). You are evaluating the accuracy and quality of another LLM's vulnerability analysis against the ground truth database.
    
    CVE ID: {0}
    
    Candidate LLM Analysis (to be evaluated):
    {1}
    
    Ground Truth (CISA Vulnrichment Data):
    {2}
    
    Evaluate how well the candidate LLM's analysis matches the ground truth. 
    Consider accuracy of the description, severity/impact, and any SSVC or action decisions provided.
    
    Please provide the following:
    1. Score: An integer score from 1 to 10, where 10 is a perfect match and 1 is completely inaccurate or hallucinated.
    2. Reasoning: A brief 1-2 sentence explanation of why this score was given, noting any missing or hallucinated information.
    3. Accuracy: A single word rating ("High", "Medium", or "Low").
    
    Provide the output in valid JSON format ONLY, with the keys: 
    "score", "reasoning", "accuracy".
    """.format(cve_id, json.dumps(log_context, indent=2), json.dumps(vuln_data, indent=2))
    
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
        import sys
        sys.stdout.write("Model generated output: ")
        sys.stdout.flush()
        for line in response.iter_lines():
            if line:
                chunk = json.loads(line)
                content = chunk.get("message", {}).get("content", "")
                result_text += content
                sys.stdout.write(content)
                sys.stdout.flush()
        sys.stdout.write("\n")
        
        # Try to parse the JSON returned by the model
        try:
            return json.loads(result_text)
        except json.JSONDecodeError:
            # Fallback if the model didn't return perfect JSON
            return {"raw_output": result_text}
            
    except RequestException as e:
        print("Error communicating with Ollama for {}: {}".format(cve_id, e))
        return {"error": str(e)}

def main():
    import sys
    
    # Default to LOG_DIR if no argument provided
    base_input_dir = LOG_DIR
    if len(sys.argv) > 1:
        base_input_dir = sys.argv[1]

    if not os.path.exists(base_input_dir):
        print("Directory {} not found.".format(base_input_dir))
        return
        
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Use os.walk to find all json files recursively
    log_files = []
    for root, dirs, files in os.walk(base_input_dir):
        for f in files:
            if f.endswith('.json'):
                log_files.append(os.path.join(root, f))
                
    print("Found {} log files in {}. Beginning processing...".format(len(log_files), base_input_dir))

    for file_path in log_files:
        print("\nProcessing {}...".format(file_path))
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
        except Exception as e:
            print("Could not read {}: {}".format(file_path, e))
            continue

        cves = extract_cves(log_data)
        if not cves:
            print("No CVEs found in {}.".format(file_path))
            continue
            
        print("Found CVEs: {}".format(', '.join(cves)))
        
        results = []
        for cve in cves:
            print("Fetching Vulnrichment data for {}...".format(cve))
            vuln_data = get_vulnrichment_data(cve)
            
            # Narrow down log_context if it's structured
            cve_context = log_data
            if isinstance(log_data, dict) and "vulnerabilities" in log_data:
                cve_context = [v for v in log_data["vulnerabilities"] if v.get("vulnerability_id") == cve]
            
            print("Performing LLM-J analysis for {} with {}...".format(cve, OLLAMA_MODEL))
            analysis = analyze_with_llmj(cve, cve_context, vuln_data)
            
            result_entry = {
                "source_log": os.path.basename(file_path),
                "cve_id": cve,
                "vulnrichment_status": "Found" if "error" not in vuln_data else vuln_data["error"],
                "llmj_analysis": analysis
            }
            results.append(result_entry)

        # Save outputs per file
        rel_dir = os.path.relpath(os.path.dirname(file_path), base_input_dir)
        input_dir_name = os.path.basename(os.path.abspath(base_input_dir))
        
        # Determine current output directory while preserving the folder hierarchy
        if rel_dir == '.':
            current_output_dir = os.path.join(OUTPUT_DIR, input_dir_name)
        else:
            current_output_dir = os.path.join(OUTPUT_DIR, input_dir_name, rel_dir)
            
        if not os.path.exists(current_output_dir):
            os.makedirs(current_output_dir)

        output_filename = "llm-j-{}".format(os.path.basename(file_path))
        output_filepath = os.path.join(current_output_dir, output_filename)
        
        print("\nSaving results to {}...".format(output_filepath))
        with open(output_filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        
    print("\nAnalysis complete!")

if __name__ == '__main__':
    main()
