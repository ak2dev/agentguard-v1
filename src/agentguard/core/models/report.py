"""The report: the only contract between the engine and any UI."""

from __future__ import annotations

import datetime as dt
from typing import Literal

from pydantic import BaseModel, Field

from .component import Artifact, Component
from .enums import Severity
from .finding import Finding, FlowPath
from .source import ImmutableRef, SourceRef

REPORT_SCHEMA_VERSION = "1.0"


class RulePackInfo(BaseModel):
    version: str
    digest: str
    rule_count: int


class AnalyzerRun(BaseModel):
    id: str
    status: Literal["ran", "skipped", "errored"]
    reason: str = ""


class LimitEvent(BaseModel):
    kind: str  # too_large | too_many_files | too_deep | symlink | hardlink | special_file | path_escape | archive_bomb | ...
    path: str
    detail: str = ""


class ReportStats(BaseModel):
    files_scanned: int = 0
    bytes_scanned: int = 0
    components: int = 0
    rules_evaluated: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    suppressed: int = 0
    limit_events: list[LimitEvent] = Field(default_factory=list)


class Report(BaseModel):
    schema_version: Literal["1.0"] = REPORT_SCHEMA_VERSION
    engine_version: str
    rule_pack: RulePackInfo
    target: SourceRef | ImmutableRef | None = None
    network_features_used: list[str] = Field(default_factory=list)
    network_hosts: list[str] = Field(default_factory=list)
    analyzers: list[AnalyzerRun] = Field(default_factory=list)
    inventory: list[Component] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    suppressed_findings: list[Finding] = Field(default_factory=list)
    flows: list[FlowPath] = Field(default_factory=list)
    stats: ReportStats = Field(default_factory=ReportStats)
    fail_on: Severity = Severity.high
    summary: str = ""
    generated_at: dt.datetime | None = None

    def exit_code(self) -> int:
        if any(a.status == "errored" for a in self.analyzers):
            return 2
        return 1 if any(f.severity.at_least(self.fail_on) for f in self.findings) else 0
