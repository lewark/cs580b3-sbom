import json
import os
import sys

def parse_agent_log(input_file, output_dir):
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print("Parsing log file: " + input_file)
    
    try:
        with open(input_file, 'r') as f:
            log_data = json.load(f)
            
        # The agent's final JSON string is usually in the content of the very last message where role == assistant
        final_content = None
        for message in reversed(log_data):
            if message.get("role") == "assistant" and "content" in message:
                if message["content"].strip().startswith("{"):
                    final_content = message["content"]
                    break
                    
        if not final_content:
            print("Could not find a valid JSON response from the agent in the log file.")
            sys.exit(1)
            
        # Parse the stringified JSON content back into a Python dictionary
        try:
            parsed_json = json.loads(final_content)
        except ValueError as decode_err:
            print("Agent's final content was not valid JSON. Error: " + str(decode_err))
            # Try to handle common LLM output mistakes (like wrapping in markdown block)
            if "```json" in final_content:
                cleaned = final_content.split("```json")[-1].split("```")[0].strip()
                parsed_json = json.loads(cleaned)
            else:
                sys.exit(1)

        # Build output filename
        base_name = os.path.basename(input_file)
        out_name = "parsed_" + base_name
        out_path = os.path.join(output_dir, out_name)
        
        # Write the cleanly formatted JSON
        with open(out_path, 'w') as out_f:
            json.dump(parsed_json, out_f, indent=4)
            
        print("Successfully extracted and formatted JSON to: " + out_path)
        
    except Exception as e:
         print("Error processing " + input_file + ": " + str(e))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parser.py <path_to_log_json>")
        sys.exit(1)
        
    input_file_path = sys.argv[1]
    # Default output directory relative to where the parser script lives
    output_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parsed-logs")
    
    parse_agent_log(input_file_path, output_directory)