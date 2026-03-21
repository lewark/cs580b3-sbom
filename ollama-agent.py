import json
import os
import shlex
import subprocess
import sys
import time

import ollama
from pydantic import BaseModel

# Streaming and tool-calling code based on https://docs.ollama.com/capabilities/tool-calling#python

MANUAL_APPROVE_COMMANDS = False

SYSTEM = """Analyze this project to identify vulnerabilities in any software dependencies. 

IMPORTANT EFFICIENCY CONSTRAINTS:
1. Identify the EXACT version of the product/codebase you are looking at.
2. Structure your analysis around that specific version only.
3. DO NOT waste time evaluating, listing, or discussing vulnerabilities for other versions of the product. Only report vulnerabilities that are known to actively affect the specific version you found in the directory.
4. Perform a CURSORY review only. Do not spend excessive time exhaustively reading every single dependency file. A quick glance at the main project files is sufficient.

Your final response MUST be a structured valid JSON object containing only the list of vulnerabilities found. 
Each vulnerability must include 'dependency_name', 'vulnerability_id' (e.g. CVE-XXXX-XXXX), 'description', and an 'ssvc_decision' which must be exactly one of: "Track", "Track*", "Attend", or "Act".

Example output format:
{
  "vulnerabilities": [
    {
      "dependency_name": "log4j",
      "vulnerability_id": "CVE-2021-44228",
      "description": "Remote Code Execution vulnerability in Log4j",
      "ssvc_decision": "Act"
    }
  ]
}"""


def run_command(command: str) -> str:
    """Execute a shell command in the current directory

    Args:
        command: The command to execute, including arguments

    Returns:
        The command's output
    """

    print("Attempting to run command", command)

    if MANUAL_APPROVE_COMMANDS:
        if input("OK? (Y/N)").lower() != "y":
            print("Skipping command")
            return "Command disallowed by user"

    split = shlex.split(command)
    if split[0] == "cd":
        n_params = len(split)
        if n_params == 1:
            target_dir = os.environ["HOME"]
        elif n_params == 2:
            target_dir = split[1]
        else:
            return "cd: too many arguments"

        if os.path.isdir(target_dir):
            os.chdir(target_dir)
            return ""
        elif os.path.exists(target_dir):
            return f"cd: {target_dir}: Not a directory"
        else:
            return f"cd: {target_dir}: No such file or directory"

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, encoding="utf-8")
    return result.stdout


def stream_message(stream) -> tuple[str, str, list]:
    thinking = []
    content = []
    tool_calls = []

    done_thinking = False
    for chunk in stream:
        if chunk.message.thinking:
            thinking.append(chunk.message.thinking)
            print(chunk.message.thinking, end='', flush=True)
        if chunk.message.content:
            if not done_thinking:
                done_thinking = True
                print('\n[Done thinking.]\n')
            content.append(chunk.message.content)
            print(chunk.message.content, end='', flush=True)
        if chunk.message.tool_calls:
            tool_calls.extend(chunk.message.tool_calls)
            print(chunk.message.tool_calls)

    return "".join(thinking), "".join(content), tool_calls


def do_chat(model: str, client: ollama.Client, messages: list) -> bool:
    stream = client.chat(model=model, messages=messages, tools=[run_command], stream=True, think=True)
    thinking, content, tool_calls = stream_message(stream)

    if thinking or content or tool_calls:
        messages.append({'role': 'assistant', 'thinking': thinking, 'content': content, 'tool_calls': tool_calls})

    if tool_calls:
        for call in tool_calls:
            print(call.function.name, call.function.arguments)
            if call.function.name == "run_command":
                result = run_command(**call.function.arguments)
            else:
                result = "Unknown tool"

            print(result)
            messages.append({"role": "tool", "tool_name": call.function.name, "content": result})
        return True
    else:
        # If message contains no tool calls, assume model is done analyzing project
        return False


def write_log_file(model: str, messages: list, out_dir: str):
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    model_label = model.replace(":", "_")

    filename =  f"{model_label}_{timestamp}.json"
    filename = os.path.join(out_dir, filename)

    entries = []
    for msg in messages:
        if isinstance(msg, dict):
            if "tool_calls" in msg:
                msg["tool_calls"] = [call.model_dump() for call in msg["tool_calls"]]
            entries.append(msg)
        else:
            entries.append(msg.model_dump())

    with open(filename, "w") as out_file:
        json.dump(entries, out_file, indent=2)


def main():
    if len(sys.argv) < 2:
        print("Usage: ollama-agent MODEL")
        sys.exit(1)

    model = sys.argv[1]
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    out_dir = os.getenv("OUTPUT_DIRECTORY", "/data/logs")

    client = ollama.Client(host=host)
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": "Please perform a cursory, high-level analysis of the codebase in the current directory to identify vulnerabilities in major software dependencies. Take a quick glance using the run_command tool. Do not be overly thorough. Once you have finished your fast analysis, provide your final response strictly in the JSON format requested, without any enclosing text or markdown formatting."}
    ]
    
    while True:
        if not do_chat(model, client, messages):
            break

    write_log_file(model, messages, out_dir)


if __name__ == "__main__":
    main()
