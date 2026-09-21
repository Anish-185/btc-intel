"""Config loader. Every stage reads values from config.yaml through here."""

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
DEFAULT_PATH = ROOT / "config.yaml"


@lru_cache(maxsize=8)
def load(path: str | Path = DEFAULT_PATH) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text())


def get(dotted: str, path: str | Path = DEFAULT_PATH) -> Any:
    """get("risk_weights.rules") -> 0.35. Raises KeyError on a missing key."""
    node: Any = load(path)
    for part in dotted.split("."):
        node = node[part]
    return node


def field(name: str, path: str | Path = DEFAULT_PATH) -> str:
    """Our canonical field name -> the column name in the incoming dataset."""
    return load(path)["schema"][name]
