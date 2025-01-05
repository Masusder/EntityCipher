import json
import re
import os

def is_valid_json(input_text):
    if not input_text.strip():
        return True
    try:
        json.loads(input_text)
        return True
    except json.JSONDecodeError:
        return False


def parse_json(input_text):
    if not input_text.strip():
        raise ValueError("Input is empty or just whitespace, cannot be valid JSON.")

    try:
        return json.loads(input_text)
    except json.JSONDecodeError:
        raise ValueError("Input is not valid JSON.")

def is_valid_version(version):
    """
    Checks if the version matches the pattern `<major>.<minor>.<hotfix>_<branch>`.

    Args:
        version (str): The version string to validate.

    Returns:
        bool: True if the version is valid, False otherwise.
    """
    pattern = r'^\d+\.\d+\.\d+_(live|qa|ptb|dev|stage|cert|uat)$'
    return bool(re.match(pattern, version))

def parse_version(version):
    """
    Splits a valid version string into its components: version number and branch.

    Args:
        version (str): The version string to parse.

    Returns:
        tuple: A tuple containing the version number and branch, or None if invalid.
    """
    if not is_valid_version(version):
        return None

    # Split the version into two parts: version and branch
    version, branch = version.rsplit('_', 1)
    return version, branch

def read_file(file_name):
    """Read the entire content of a file."""
    file_path = os.path.join('data', file_name)
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"The file at {file_path} was not found.")
    except IOError as e:
        raise IOError(f"Error reading the file at {file_path}: {e}")

def write_to_file(file_name, content):
    """Write content to a file, overwriting the file if it exists."""
    file_path = os.path.join('data', file_name)
    try:
        with open(file_path, 'w') as file:
            file.write(content)
    except IOError as e:
        raise IOError(f"Error writing to the file at {file_path}: {e}")
