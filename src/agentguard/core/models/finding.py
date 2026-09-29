"""Findings, evidence, locations, mappings, scores, flows."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..redact import RedactedText
from .enums import CapLabel, Confidence, EvidenceKind, FindingSource, Severity


class Span(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int = 1
    start_col: int = 1
    end_line: int | None = None
    end_col: int | None = None

    def key(self) -> tuple[str, int, int]:
        return (self.path, self.start_line, self.start_col)


class Evidence(BaseModel):
    kind: EvidenceKind
    location: Span | None = None
    snippet: RedactedText = RedactedText.of("")
    detail: str = ""
    hidden: bool = False
    decode_path: list[str] = Field(default_factory=list)
    taint_path: list[Span] | None = None


FRAMEWORKS = (
    "owasp-asi-2026",
    "owasp-mcp-2025-beta",
    "owasp-ast-1.0",
    "owasp-llm-2025",
    "nsa-csi-mcp-2026-05",
    "cwe",
)


class Mapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    framework: str
    id: str | None = None
    title: str | None = None
    todo: str | None = None

    @model_validator(mode="after")
    def _id_or_todo(self) -> Mapping:
        if self.framework not in FRAMEWORKS:
            raise ValueError(f"unknown framework {self.framework!r}")
        if self.id is None and not self.todo:
            raise ValueError("a mapping without an id must carry a todo note")
        return self


class Score(BaseModel):
    scorer: str
    scorer_version: str
    value: float
    vector: str = ""
    components: dict[str, float] = Field(default_factory=dict)


class FlowPath(BaseModel):
    nodes: list[str]
    edges: list[tuple[str, str, str]] = Field(default_factory=list)
    labels: dict[str, list[CapLabel]] = Field(default_factory=dict)
    narrative: str = ""


class SuppressionState(BaseModel):
    status: str  # "active" | "expired"
    reason: str
    expires: str


class Finding(BaseModel):
    fingerprint: str
    rule_id: str
    rule_version: int
    title: str
    severity: Severity
    confidence: Confidence
    score: Score | None = None
    source: FindingSource = FindingSource.deterministic
    component_ids: list[str] = Field(default_factory=list)
    primary: Span | None = None
    related: list[Span] = Field(default_factory=list)
    message: str
    explanation: str = ""
    remediation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    mappings: list[Mapping] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    flow: FlowPath | None = None
    suppression: SuppressionState | None = None
    baseline_state: str | None = None  # "new" | "unchanged"

    def sort_key(self) -> tuple:
        p = self.primary
        return (
            -self.severity.rank,
            self.rule_id,
            p.path if p else "",
            p.start_line if p else 0,
            p.start_col if p else 0,
            self.fingerprint,
        )
