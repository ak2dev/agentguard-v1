"""Shared loader for rule fixtures (used by tests and `agentguard rules test`)."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard.core.archive import from_archive
from agentguard.core.models import LoadLimits, Lockfile, PackageFacts, Policy, RemoteProbe, ScanOptions, Suppression
from agentguard.core.parsers.safe_yaml import safe_load
from agentguard.core.tree import ArtifactTree
from agentguard.io.fs_loader import load_path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures" / "rules"
CONTROL_FILES = ("_case.yaml", "_archive.zip", "agentguard.lock")


@dataclass
class Case:
    rule_id: str
    side: str
    name: str
    path: Path
    tree: ArtifactTree
    options: ScanOptions
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.rule_id}/{self.side}/{self.name}"


def load_case(rule_id: str, side: str, case_dir: Path) -> Case:
    cfg: dict[str, Any] = {}
    if (case_dir / "_case.yaml").exists():
        res = safe_load((case_dir / "_case.yaml").read_text(encoding="utf-8"))
        assert res.error is None, res.error
        cfg = res.value or {}
    limits = LoadLimits(**cfg.get("limits", {}))
    if (case_dir / "_archive.zip").exists():
        tree = from_archive((case_dir / "_archive.zip").read_bytes(), limits=limits)
    else:
        tree = load_path(case_dir, limits)
        for name in CONTROL_FILES:
            tree.files.pop(name, None)
    opts: dict[str, Any] = {"limits": limits}
    if "popular_skills" in cfg:
        opts["popular_skills"] = cfg["popular_skills"]
    if "policy" in cfg:
        opts["policy"] = Policy.model_validate(cfg["policy"])
    if (case_dir / "agentguard.lock").exists():
        opts["lock"] = Lockfile.model_validate_json((case_dir / "agentguard.lock").read_text(encoding="utf-8"))
    if "network" in cfg:
        opts["network"] = cfg["network"]
    if "suppressions" in cfg:
        opts["suppressions"] = [Suppression.model_validate(s) for s in cfg["suppressions"]]
    if "today" in cfg:
        opts["today"] = dt.date.fromisoformat(str(cfg["today"]))
    if "remote_probes" in cfg:
        opts["remote_probes"] = [RemoteProbe.model_validate(x) for x in cfg["remote_probes"]]
    if "package_facts" in cfg:
        opts["package_facts"] = [PackageFacts.model_validate(x) for x in cfg["package_facts"]]
    if cfg.get("intel"):
        from agentguard.io.intel_store import bundled_intel_dir, trusted_keys
        from agentguard.core.intel.feed import verify_feed

        d = bundled_intel_dir()
        opts["intel"] = verify_feed((d / "sample-feed.json").read_bytes(), (d / "sample-feed.json.sig").read_bytes(), trusted_keys())
    if "changed_paths" in cfg:
        opts["changed_paths"] = set(cfg["changed_paths"])
    return Case(rule_id, side, case_dir.name, case_dir, tree, ScanOptions(**opts), cfg)


def iter_cases(rule_ids: list[str]) -> list[tuple[str, str, Path]]:
    out = []
    for rule_id in rule_ids:
        for side in ("positive", "negative"):
            d = FIXTURES / rule_id / side
            if d.is_dir():
                for case in sorted(p for p in d.iterdir() if p.is_dir()):
                    out.append((rule_id, side, case))
    return out
