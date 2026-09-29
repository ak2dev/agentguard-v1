"""The single redaction choke point.

Every snippet that can reach any output format is a ``RedactedText``. Pydantic
validation of a plain ``str`` into a ``RedactedText`` field *always* runs
``redact_snippet``, so a caller cannot put raw scanned text in a report by
accident. Redaction format: first 4 chars + ``…`` + ``[`` 8-hex sha256 ``]``.
"""

from __future__ import annotations

from typing import Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

from .secrets import find_secrets
from .textutil import short_hash, visible_escape

MAX_SNIPPET = 240


def redact_value(secret: str) -> str:
    return f"{secret[:4]}…[{short_hash(secret)}]"


def redact_secrets(text: str) -> str:
    matches = find_secrets(text)
    if not matches:
        return text
    out: list[str] = []
    pos = 0
    for m in matches:
        out.append(text[pos : m.start])
        out.append(redact_value(m.value))
        pos = m.end
    out.append(text[pos:])
    return "".join(out)


def redact_snippet(text: str, max_len: int = MAX_SNIPPET) -> str:
    # Redact on the full text first so truncation can never split a secret.
    cleaned = visible_escape(redact_secrets(text))
    cleaned = cleaned.replace("\r\n", "\n").strip("\n")
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1] + "…"
    return cleaned


class RedactedText(str):
    """A string that has passed through ``redact_snippet``."""

    __slots__ = ()

    @classmethod
    def of(cls, text: str, max_len: int = MAX_SNIPPET) -> RedactedText:
        if isinstance(text, RedactedText):
            return text
        return str.__new__(cls, redact_snippet(text, max_len))

    @classmethod
    def __get_pydantic_core_schema__(cls, source: Any, handler: GetCoreSchemaHandler):
        return core_schema.no_info_after_validator_function(
            cls.of,
            core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(str),
        )
