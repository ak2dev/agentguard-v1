"""Where scanned content came from.

``SourceRef`` is what a user supplied; ``ImmutableRef`` is what was actually
scanned (a commit SHA, an exact package version, an image digest). Agent Guard
Web keys its cache on ``ImmutableRef`` plus the rule-pack digest.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .enums import SourceKind


class SourceRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: SourceKind
    locator: str
    subpath: str | None = None


class ImmutableRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: SourceKind
    locator: str
    resolved: str
    integrity: str | None = None
    # e.g. "https://github.com/o/r/blob/{resolved}/{path}#L{line}"
    source_url_template: str | None = None

    def url_for(self, path: str, line: int | None = None) -> str | None:
        if not self.source_url_template:
            return None
        return self.source_url_template.format(
            resolved=self.resolved, path=path, line=line if line is not None else 1
        )
