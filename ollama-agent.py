import subprocess

import ollama

# Streaming and tool-calling code based on https://docs.ollama.com/capabilities/tool-calling#python

MANUAL_APPROVE_COMMANDS = True
MODEL = "qwen3.5:9b"
HOST = "http://localhost:11434"

SYSTEM = "Analyze this project to identify vulnerabilities in any software dependencies. List each vulnerability found (if any), along with an SSVC decision (Track, Track*, Attend, or Act)."


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
                print('\n...Done thinking.\n')
            content.append(chunk.message.content)
            print(chunk.message.content, end='', flush=True)
        if chunk.message.tool_calls:
            tool_calls.extend(chunk.message.tool_calls)
            print(chunk.message.tool_calls)

    return "".join(thinking), "".join(content), tool_calls


def do_chat(client: ollama.Client, messages: list) -> bool:
    stream = client.chat(model=MODEL, messages=messages, tools=[run_command], stream=True, think=True)
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


def main():
    client = ollama.Client(host=HOST)
    messages = [{"role": "system", "content": SYSTEM}]
    while True:
        if not do_chat(client, messages):
            break


if __name__ == "__main__":
    main()
