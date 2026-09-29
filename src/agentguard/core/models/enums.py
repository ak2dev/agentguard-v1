"""Enumerations shared by every model. Values are part of the report schema."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def bump(self, levels: int = 1) -> Severity:
        order = list(reversed(_SEV_ORDER))  # info .. critical
        idx = min(max(order.index(self) + levels, 0), len(order) - 1)
        return order[idx]

    @classmethod
    def parse(cls, value: str) -> Severity:
        v = value.strip().lower()
        aliases = {"crit": "critical", "med": "medium", "moderate": "medium", "none": "info"}
        return cls(aliases.get(v, v))


_SEV_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
_SEV_RANK = {s: len(_SEV_ORDER) - i for i, s in enumerate(_SEV_ORDER)}


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}[self.value]

    def lower(self, levels: int = 1) -> Confidence:
        order = [Confidence.low, Confidence.medium, Confidence.high]
        return order[max(order.index(self) - levels, 0)]

    @staticmethod
    def min(*values: Confidence) -> Confidence:
        return min(values, key=lambda c: c.rank)


class SourceKind(StrEnum):
    local = "local"
    npm = "npm"
    pypi = "pypi"
    oci = "oci"
    github = "github"
    gist = "gist"
    raw_url = "raw_url"
    mcp_registry = "mcp_registry"
    marketplace = "marketplace"
    remote_mcp = "remote_mcp"
    pasted = "pasted"


class ComponentKind(StrEnum):
    agent_host = "agent_host"
    skill = "skill"
    instruction_file = "instruction_file"
    subagent = "subagent"
    command = "command"
    mcp_server = "mcp_server"
    mcp_client_config = "mcp_client_config"
    package = "package"


class ArtifactRole(StrEnum):
    skill_md = "skill_md"
    instruction_md = "instruction_md"
    script = "script"
    reference = "reference"
    asset = "asset"
    client_config = "client_config"
    server_json = "server_json"
    tool_manifest = "tool_manifest"
    source_code = "source_code"
    package_manifest = "package_manifest"
    lockfile = "lockfile"
    ui_resource = "ui_resource"
    binary = "binary"
    archive = "archive"
    other = "other"


class Transport(StrEnum):
    stdio = "stdio"
    streamable_http = "streamable_http"
    sse_deprecated = "sse_deprecated"
    unknown = "unknown"


class CapLabel(StrEnum):
    reads_private_data = "reads_private_data"
    ingests_untrusted_content = "ingests_untrusted_content"
    external_egress = "external_egress"
    destructive = "destructive"
    code_exec = "code_exec"
    # Sub-labels used for escalation and explanations.
    credential_access = "credential_access"
    persistence = "persistence"
    auto_approved = "auto_approved"


TRIFECTA = (
    CapLabel.reads_private_data,
    CapLabel.ingests_untrusted_content,
    CapLabel.external_egress,
)


class FindingSource(StrEnum):
    deterministic = "deterministic"
    llm = "llm"
    intel = "intel"
    policy = "policy"


class EvidenceKind(StrEnum):
    regex = "regex"
    yara = "yara"
    ast = "ast"
    taint = "taint"
    schema = "schema"
    config = "config"
    metadata = "metadata"
    intel = "intel"
    lock_diff = "lock_diff"
    llm = "llm"
    policy = "policy"
    loader = "loader"
