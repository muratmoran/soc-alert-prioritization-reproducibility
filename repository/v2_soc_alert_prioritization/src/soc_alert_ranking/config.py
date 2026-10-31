"""Configuration helpers for the v2 project."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "configs"


def load_yaml(path: str | Path) -> Dict[str, Any]:
    """Load a YAML file.

    PyYAML is listed in the v2 requirements. Keeping this helper centralized
    makes it easy to replace the parser if the environment changes.
    """

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RuntimeError("Install PyYAML to load v2 configuration files.") from exc

    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return data


def load_config(name: str) -> Dict[str, Any]:
    """Load a config by file stem from the v2 configs directory."""

    path = CONFIG_DIR / f"{name}.yaml"
    return load_yaml(path)
