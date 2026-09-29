"""JSON Schemas for Agent Guard's data formats (generated from the Pydantic
models; committed under schemas/ and checked for staleness in CI)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import Lockfile, Policy, ProjectConfig, Report, RuleDef

SCHEMA_BASE = "https://agentguard.dev/schemas"


def _schema(model: type, name: str, version: str) -> Callable[[], dict[str, Any]]:
    def build() -> dict[str, Any]:
        s = model.model_json_schema(mode="serialization")
        s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        s["$id"] = f"{SCHEMA_BASE}/{name}.v{version}.json"
        return s

    return build


SCHEMAS: dict[str, Callable[[], dict[str, Any]]] = {
    "report": _schema(Report, "report", "1"),
    "rule": _schema(RuleDef, "rule", "1"),
    "lock": _schema(Lockfile, "lock", "1"),
    "policy": _schema(Policy, "policy", "1"),
    "config": _schema(ProjectConfig, "config", "1"),
}
