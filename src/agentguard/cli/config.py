"""Loading .agentguard.yaml, policy files and baselines (host side)."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from ..core.models import Policy, ProjectConfig
from ..core.parsers.safe_yaml import safe_load

CONFIG_NAMES = (".agentguard.yaml", ".agentguard.yml")


class ConfigError(ValueError):
    pass


def parse_project_config(text: str, origin: str) -> ProjectConfig:
    res = safe_load(text)
    if res.error:
        raise ConfigError(f"{origin}: {res.error}")
    try:
        return ProjectConfig.model_validate(res.value or {})
    except ValidationError as exc:
        raise ConfigError(f"{origin}: {exc.errors()[0]['msg']} at {'.'.join(map(str, exc.errors()[0]['loc']))}") from exc


def find_project_config(root: Path) -> Path | None:
    base = root if root.is_dir() else root.parent
    for name in CONFIG_NAMES:
        if (base / name).is_file():
            return base / name
    return None


def load_policy(path: Path) -> Policy:
    res = safe_load(path.read_text(encoding="utf-8"))
    if res.error:
        raise ConfigError(f"{path}: {res.error}")
    try:
        return Policy.model_validate(res.value or {})
    except ValidationError as exc:
        raise ConfigError(f"{path}: {exc.errors()[0]['msg']}") from exc


def load_baseline(path: Path) -> set[str]:
    """Accept either a previous Agent Guard JSON report or {"fingerprints": [...]}."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        return {str(x) for x in data["fingerprints"]}
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return {str(f.get("fingerprint")) for f in data["findings"] if isinstance(f, dict) and f.get("fingerprint")}
    raise ConfigError(f"{path}: not a baseline or Agent Guard report")
