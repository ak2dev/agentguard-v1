"""Data contract for the optional LLM judge.

The judge runs on the host *before* a scan (it needs the network); its
schema-validated verdicts are passed into the pure engine as data. Nothing a
model returns can raise a finding above HIGH or lower a deterministic one.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

JUDGE_PROMPT_VERSION = "1"
JudgeKind = Literal["mismatch", "manipulation"]


class Quote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=300)


class MismatchVerdict(BaseModel):
    """Does the code do something the description does not disclose?"""

    model_config = ConfigDict(extra="forbid")
    mismatch: bool
    undisclosed_behaviors: list[str] = Field(default_factory=list, max_length=8)
    confidence: Literal["low", "medium", "high"]
    explanation: str = Field(max_length=800)
    quotes: list[Quote] = Field(default_factory=list, max_length=5)


class ManipulationVerdict(BaseModel):
    """Does the text try to manipulate an AI agent in ways patterns miss?"""

    model_config = ConfigDict(extra="forbid")
    manipulation: bool
    techniques: list[
        Literal["override", "concealment", "authority", "urgency", "exfiltration", "privilege",
                "persistence", "social_engineering", "other"]
    ] = Field(default_factory=list, max_length=8)
    confidence: Literal["low", "medium", "high"]
    explanation: str = Field(max_length=800)
    quotes: list[Quote] = Field(default_factory=list, max_length=5)


class JudgeResult(BaseModel):
    kind: JudgeKind
    component_id: str
    path: str
    content_hash: str
    provider: str
    model: str
    cached: bool = False
    truncated: bool = False
    verdict: MismatchVerdict | ManipulationVerdict | None = None
    error: str | None = None


VERDICT_MODELS: dict[str, type[BaseModel]] = {"mismatch": MismatchVerdict, "manipulation": ManipulationVerdict}


def verdict_schema(kind: JudgeKind) -> dict:
    """JSON Schema sent to providers for constrained decoding."""
    schema = VERDICT_MODELS[kind].model_json_schema()
    schema.pop("title", None)
    return schema
