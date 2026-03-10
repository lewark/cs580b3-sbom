import shlex
import subprocess

import ollama

# Based on https://docs.ollama.com/capabilities/tool-calling#python

SYSTEM = "Analyze this project to identify vulnerabilities in any software dependencies. List each vulnerability found (if any), along with an SSVC decision (Track, Track*, Attend, or Act)."
MANUAL_APPROVE_COMMANDS = True
MODEL = "qwen3.5:9b"




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

    args = shlex.split(command)

    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8")
    return result.stdout


def do_chat(messages):
    response = ollama.chat(model=MODEL, messages=messages, tools=[run_command], think=True)
    messages.append(response.message)

    if response.message.tool_calls:
        for call in response.message.tool_calls:
            print(call.function.name, call.function.arguments)
            if call.function.name == "run_command":
                result = run_command(**call.function.arguments)
            else:
                result = "Unknown tool"

            print(result)
            messages.append({"role": "tool", "tool_name": call.function.name, "content": result})
    else:
        print(response.message.content)


def main():
    messages = [{"role": "system", "content": SYSTEM}]
    while True:
        do_chat(messages)


if __name__ == "__main__":
    main()
