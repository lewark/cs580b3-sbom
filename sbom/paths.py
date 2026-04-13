import os
from typing import Optional


def find_json_files(base_input_dir: str,
    required_strs: Optional[list[str]] = None,
    excluded_strs: Optional[list[str]] = None,
    required_dirs: Optional[list[str]] = None,
    excluded_dirs: Optional[list[str]] = None
) -> list[str]:
    # Use os.walk to find all json files recursively
    log_files = []

    for root, dirs, files in os.walk(base_input_dir):
        for f in files:
            path = os.path.join(root, f)
            if path.endswith(".json") and matches_path(path, required_strs, excluded_strs, required_dirs, excluded_dirs):
                log_files.append(path)

    return log_files


def matches_path(
    path: str,
    required_strs: Optional[list[str]],
    excluded_strs: Optional[list[str]],
    required_dirs: Optional[list[str]],
    excluded_dirs: Optional[list[str]]
) -> bool:
    if required_strs is not None:
        for item in required_strs:
            if item not in path:
                return False

    if excluded_strs is not None:
        for item in excluded_strs:
            if item in path:
                return False

    if (required_dirs is not None) or (excluded_dirs is not None):
        components = path.split(os.sep)

        if required_dirs is not None:
            for item in required_dirs:
                if item not in components:
                    return False

        if excluded_dirs is not None:
            for item in excluded_dirs:
                if item in components:
                    return False

    return True


def get_file_categories(path: str) -> tuple[str, str]:
    prompting_modes = ["chain-of-thought-prompt", "standard-prompt"]
    tool_modes = ["tooling", "non-tooling"]

    components = path.split(os.sep)

    return search_path_components(components, prompting_modes), search_path_components(components, tool_modes)


def search_path_components(components: list[str], options: list[str]) -> str:
    for option in options:
        if option in components:
            return option
    return "unknown"
