"""Scan options, load limits, suppressions, policy, lockfile."""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..intel.feed import IntelFeed
from .network import PackageFacts, RemoteProbe
from .enums import CapLabel, Severity


class LoadLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_file_bytes: int = 4 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_files: int = 20_000
    max_depth: int = 32
    max_archive_ratio: float = 100.0
    max_archive_members: int = 20_000
    max_decode_depth: int = 3
    max_decoded_bytes: int = 1 * 1024 * 1024
    max_yaml_nodes: int = 50_000
    max_json_depth: int = 64
    max_line_length_for_regex: int = 20_000
    excluded_dirs: tuple[str, ...] = (
        ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
        ".pytest_cache", ".agentguard-cache",
    )

    @classmethod
    def cli(cls) -> LoadLimits:
        return cls()

    @classmethod
    def ci(cls) -> LoadLimits:
        return cls()

    @classmethod
    def web(cls) -> LoadLimits:
        return cls(
            max_file_bytes=2 * 1024 * 1024,
            max_total_bytes=64 * 1024 * 1024,
            max_files=5_000,
            max_archive_members=5_000,
        )


class NetworkOptions(BaseModel):
    """Every network feature is opt-in. Enabled features appear in the report header."""

    live_metadata: bool = False
    auth_checks: bool = False
    provenance: bool = False
    osv: bool = False
    registry: bool = False

    def enabled(self) -> list[str]:
        return [k for k, v in self.model_dump().items() if v]


class Suppression(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str | None = None
    fingerprint: str | None = None
    path_glob: str | None = None
    reason: str = ""
    expires: dt.date | None = None

    @model_validator(mode="after")
    def _has_selector(self) -> Suppression:
        if not (self.rule_id or self.fingerprint or self.path_glob):
            raise ValueError("suppression needs at least one of rule_id, fingerprint, path_glob")
        return self

    def is_valid(self) -> bool:
        return len(self.reason.strip()) >= 10 and self.expires is not None


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    engine: Literal["builtin"] = "builtin"  # "rego" / "cel" reserved
    deny_servers: list[str] = Field(default_factory=list)       # glob on name / command / url
    deny_publishers: list[str] = Field(default_factory=list)
    allow_servers: list[str] | None = None
    require_pinning: bool = False
    max_severity: Severity | None = None
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    trifecta_severity: Severity = Severity.high


class ProjectConfig(BaseModel):
    """Contents of .agentguard.yaml."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    fail_on: Severity | None = None
    exclude: list[str] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)
    policy: Policy | None = None
    popular_skills: list[str] = Field(default_factory=list)


class ToolSnapshot(BaseModel):
    hash: str
    definition: dict[str, Any]


class LockEntry(BaseModel):
    key: str
    kind: str
    name: str
    version: str | None = None
    content_hash: str
    skill_files: dict[str, str] | None = None
    tools: dict[str, ToolSnapshot] | None = None
    capability_labels: list[CapLabel] = Field(default_factory=list)


class Lockfile(BaseModel):
    lock_version: Literal[1] = 1
    generator: str = "agentguard"
    entries: list[LockEntry] = Field(default_factory=list)


class JudgeOptions(BaseModel):
    provider: Literal["anthropic", "openai_compat", "ollama"]
    model: str
    endpoint: str | None = None
    budget_calls: int = 20
    cache_dir: str | None = None


class ProgressEvent(BaseModel):
    stage: str
    done: int
    total: int


class ScanOptions(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    intel: IntelFeed | None = None
    remote_probes: list[RemoteProbe] = Field(default_factory=list)
    package_facts: list[PackageFacts] = Field(default_factory=list)
    network_hosts: list[str] = Field(default_factory=list)

    fail_on: Severity = Severity.high
    limits: LoadLimits = Field(default_factory=LoadLimits)
    analyzers: set[str] | None = None           # None = all available
    network: NetworkOptions = Field(default_factory=NetworkOptions)
    judge: JudgeOptions | None = None
    policy: Policy | None = None
    suppressions: list[Suppression] = Field(default_factory=list)
    baseline: set[str] | None = None            # fingerprints
    changed_paths: set[str] | None = None
    lock: Lockfile | None = None
    popular_skills: list[str] = Field(default_factory=list)
    include_timestamps: bool = False
    today: dt.date | None = None                # for suppression expiry (determinism)
    deadline_s: float | None = None
    on_progress: Callable[[ProgressEvent], None] | None = Field(default=None, exclude=True)
