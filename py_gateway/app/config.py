import yaml
from pathlib import Path

def load_config(path: str = "config.yaml") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r") as f:
        return yaml.safe_load(f) or {}
