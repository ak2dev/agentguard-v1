"""Inventory: components, MCP server specs, tool/prompt/resource definitions,
capabilities, artifacts."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from ..textutil import sha256_hex
from .enums import (
    ArtifactRole,
    CapLabel,
    ComponentKind,
    Confidence,
    Transport,
)
from .finding import Evidence, Span
from .source import ImmutableRef, SourceRef


def canonical_json(value: Any) -> str:
    """Deterministic JSON (sorted keys, no whitespace, UTF-8). Close to RFC 8785
    for the value space we hash (no floats with exotic representations)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class McpServerSpec(BaseModel):
    transport: Transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    env_names: list[str] = Field(default_factory=list)
    header_names: list[str] = Field(default_factory=list)
    pinned: bool = False
    pin_detail: str | None = None
    client: str = "unknown"
    scope: str = "unknown"  # user | project | enterprise | workspace | unknown
    config_path: str = ""
    config_span: Span | None = None


class ToolDef(BaseModel):
    name: str
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = Field(default_factory=dict)
    origin: str = "manifest"  # manifest | server_json | source_extraction | live_list
    span: Span | None = None

    def canonical(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "input_schema": self.input_schema,
            "annotations": self.annotations,
        }

    def normalized_hash(self) -> str:
        return sha256_hex(canonical_json(self.canonical()))


class PromptDef(BaseModel):
    name: str
    title: str | None = None
    description: str | None = None
    arguments: list[dict[str, Any]] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)
    span: Span | None = None


class ResourceDef(BaseModel):
    uri: str
    name: str | None = None
    title: str | None = None
    description: str | None = None
    mime_type: str | None = None
    text: str | None = None  # for ui:// resources supplied statically
    span: Span | None = None


class Capability(BaseModel):
    label: CapLabel
    subject: str  # component id or "component_id#tool"
    declared: bool = False
    observed: bool = False
    confidence: Confidence = Confidence.medium
    evidence: list[Evidence] = Field(default_factory=list)
    reason: str = ""


class Artifact(BaseModel):
    id: str
    component_id: str
    path: str
    role: ArtifactRole
    language: str | None = None
    sha256: str
    size: int


class Component(BaseModel):
    id: str
    kind: ComponentKind
    name: str
    version: str | None = None
    publisher: str | None = None
    source: SourceRef | ImmutableRef | None = None
    content_hash: str = ""
    root: str = ""  # path of the component's root inside the scanned tree
    server: McpServerSpec | None = None
    artifact_ids: list[str] = Field(default_factory=list)
    tools: list[ToolDef] = Field(default_factory=list)
    prompts: list[PromptDef] = Field(default_factory=list)
    resources: list[ResourceDef] = Field(default_factory=list)
    instructions: str | None = None
    capabilities: list[Capability] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    def labels(self) -> set[CapLabel]:
        return {c.label for c in self.capabilities}


def component_id(kind: ComponentKind | str, *parts: str) -> str:
    return sha256_hex("|".join([str(kind), *parts]))[:16]
