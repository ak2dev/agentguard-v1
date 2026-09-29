"""Rule definitions (the rule pack is data; see rules/*.yaml)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import Confidence, Severity
from .finding import Mapping

RULE_ID_RE = r"^AG-[A-Z]+(?:-[A-Z]+)?-\d{3}$"

TextScope = Literal[
    "body",          # visible markdown body / whole text for non-markdown
    "frontmatter",   # serialized frontmatter values
    "hidden",        # comments, alt text, post-whitespace text, tag-char payloads
    "decoded",       # decoded blobs (base64/hex/…)
    "code",          # script / source files
    "tool_text",     # MCP tool/param/prompt/resource descriptive text
    "server_instructions",
    "command",       # shell commands (config commands, `!` injections, hooks)
]


class RegexMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["regex"] = "regex"
    patterns: list[str]
    scopes: list[TextScope] = Field(default_factory=lambda: ["body", "hidden", "decoded"])
    # All of these must also match within `window` lines of the primary match.
    require: list[str] = Field(default_factory=list)
    # A match is discarded if any of these match within `window` lines.
    unless: list[str] = Field(default_factory=list)
    window: int = 3
    ignore_case: bool = True
    # Only match inside sections whose heading matches one of these.
    sections: list[str] = Field(default_factory=list)
    # Confidence is lowered one level when the match sits in a fenced code block.
    lower_confidence_in_code: bool = False
    max_matches: int = 5


class AnalyzerMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["analyzer"] = "analyzer"
    analyzer: str
    params: dict = Field(default_factory=dict)


class YaraMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["yara"] = "yara"
    rule_file: str


MatchSpec = Annotated[RegexMatch | AnalyzerMatch | YaraMatch, Field(discriminator="type")]


class AivssDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Threat Multiplier status per AIVSS v0.8: attacked | poc | unreported
    threat: Literal["attacked", "poc", "unreported"] = "poc"
    # CVSS v4.0 base score computed with the FIRST calculator for cvss4_vector.
    # When absent the scorer falls back to a severity default and says so.
    cvss_base: float | None = None


class RuleDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=RULE_ID_RE)
    version: int = Field(ge=1)
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    applies_to: list[str] = Field(default_factory=list)
    match: MatchSpec
    # Filled from mappings/crosswalk.yaml at load time (the crosswalk is data).
    mappings: list[Mapping] = Field(default_factory=list)
    remediation: str
    why: str = ""
    references: list[str] = Field(default_factory=list)
    cvss4_vector: str | None = None
    aivss: AivssDefaults = Field(default_factory=AivssDefaults)
    tags: list[str] = Field(default_factory=list)
    network: bool = False  # rule only evaluates with an opt-in network feature
    enabled: bool = True

    @field_validator("title")
    @classmethod
    def _short_title(cls, v: str) -> str:
        if len(v) > 120:
            raise ValueError("title too long")
        return v
