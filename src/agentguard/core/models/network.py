"""Results of opt-in network features, passed into the (pure) engine as data.

Host-side collectors in ``agentguard.net`` produce these; recorded instances
double as test fixtures, so every network rule is testable offline.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, Field


class RemoteProbe(BaseModel):
    server_name: str
    url: str
    config_path: str = ""
    reachable: bool = True
    error: str | None = None
    tls_version: str | None = None
    tls_error: str | None = None
    status_unauth: int | None = None
    unauthenticated_list: bool = False
    www_authenticate: str | None = None
    prm_url: str | None = None
    prm: dict[str, Any] | None = None
    prm_error: str | None = None
    as_metadata: dict[str, dict[str, Any]] = Field(default_factory=dict)
    as_errors: dict[str, str] = Field(default_factory=dict)
    insecure_redirects: list[str] = Field(default_factory=list)
    protocol_version: str | None = None
    server_info: dict[str, Any] | None = None
    tools: list[dict[str, Any]] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    instructions: str | None = None


class Vulnerability(BaseModel):
    id: str
    severity: str = "unknown"   # critical | high | medium | low | unknown
    summary: str = ""


class PackageFacts(BaseModel):
    ecosystem: Literal["npm", "pypi"]
    name: str
    version: str | None = None
    created: dt.date | None = None
    version_published: dt.date | None = None
    provenance: Literal["present", "absent", "unknown"] = "unknown"
    provenance_mismatch: bool = False
    provenance_detail: str = ""
    publisher: str | None = None
    vulns: list[Vulnerability] = Field(default_factory=list)
    error: str | None = None
