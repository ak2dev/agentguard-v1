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


class Downgrade(BaseModel):
    """Report a regex match at a lower severity (and one level lower
    confidence) when it is a *mention* rather than a directive. Every
    condition given must hold; the first matching downgrade wins. Hidden or
    decoded matches are still escalated one level afterwards."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    # Only for artifacts in these roles (empty: any role).
    roles: list[str] = Field(default_factory=list)
    # Only when the match sits inside "double quotes", “curly quotes”, an
    # inline `code span`, or 'single quotes' hugging the match, on its line.
    quoted: bool = False
    # Only when one of these matches within `window` lines (default: the rule's).
    patterns: list[str] = Field(default_factory=list)
    window: int | None = None
    # Only when one of these matches the component's declared purpose (its
    # SKILL.md `description`): the behavior is what the skill says it does.
    declared: list[str] = Field(default_factory=list)


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
    downgrade: list[Downgrade] = Field(default_factory=list)
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
