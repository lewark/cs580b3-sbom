import os

def find_json_files(base_input_dir: str, required_strs: list[str], excluded_strs: list[str]) -> list[str]:
    # Use os.walk to find all json files recursively
    log_files = []

    for root, dirs, files in os.walk(base_input_dir):
        for f in files:
            path = os.path.join(root, f)
            if path.endswith(".json") and matches_path(path, required_strs, excluded_strs):
                log_files.append(path)

    return log_files


def matches_path(path: str, required_strs: list[str], excluded_strs: list[str]) -> bool:
    for item in required_strs:
        if item not in path:
            return False

    for item in excluded_strs:
        if item in path:
            return False

    return True
