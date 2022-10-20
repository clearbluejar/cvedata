import gzip
import json
from pathlib import Path


def get_file_json(path: Path, base: str) -> dict:
    """
    Open path and return json
    """
    try:
        if path.name.endswith(".gz"):
            with gzip.open(path) as f:
                return json.load(f)
        else:
            with open(path) as f:
                return json.load(f)
    except FileNotFoundError as e:
        raise Exception(f"Missing {path}. Please run {base}") from e