"""Secret detection shared by redaction and the literal-secret rules.

Redaction is an engine-level safety property, so these patterns live in the
engine rather than in the (separately versioned) rule pack. Redaction is
deliberately aggressive; *detection* rules additionally filter placeholders.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

import regex

from .textutil import TIMEOUT


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: regex.Pattern[str]
    group: int = 0          # capture group holding the secret value
    min_entropy: float = 0.0


def _p(expr: str, flags: int = 0) -> regex.Pattern[str]:
    return regex.compile(expr, flags | regex.VERSION1)


# Order matters: more specific patterns first (overlaps resolve to first match).
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "private_key",
        _p(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]{0,8192}?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)"),
    ),
    SecretPattern("anthropic_api_key", _p(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}")),
    SecretPattern("openai_api_key", _p(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    SecretPattern("aws_access_key_id", _p(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    SecretPattern(
        "aws_secret_access_key",
        _p(r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"),
        group=1,
    ),
    SecretPattern("github_token", _p(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    SecretPattern("github_fine_grained_pat", _p(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    SecretPattern("gitlab_token", _p(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    SecretPattern("slack_token", _p(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    SecretPattern("slack_webhook", _p(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,}")),
    SecretPattern(
        "discord_webhook",
        _p(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}"),
    ),
    SecretPattern("telegram_bot_token", _p(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
    SecretPattern("google_api_key", _p(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    SecretPattern("stripe_key", _p(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    SecretPattern("npm_token", _p(r"\bnpm_[A-Za-z0-9]{36}\b")),
    SecretPattern("pypi_token", _p(r"\bpypi-AgE[A-Za-z0-9_\-]{50,}")),
    SecretPattern("huggingface_token", _p(r"\bhf_[A-Za-z0-9]{30,}\b")),
    SecretPattern("jwt", _p(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    SecretPattern("azure_storage_key", _p(r"AccountKey=([A-Za-z0-9+/=]{40,})"), group=1),
    SecretPattern("url_credentials", _p(r"[a-z][a-z0-9+.\-]*://[^/\s:@\"']+:([^/\s@\"']{3,})@"), group=1),
    SecretPattern(
        "bearer_token",
        _p(r"(?i)\bbearer\s+([A-Za-z0-9._~+/\-]{20,}=*)"),
        group=1,
        min_entropy=3.0,
    ),
    SecretPattern(
        "generic_assignment",
        _p(
            r"(?i)\b[a-z0-9_\-]*(?:api[_\-]?key|secret|token|passw(?:or)?d|pwd|credential|auth[_\-]?key)"
            r"[a-z0-9_\-]*[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        group=1,
        min_entropy=3.2,
    ),
)

_PLACEHOLDER = regex.compile(
    r"(?i)^(?:\$\{?[A-Z0-9_]+\}?|<[^>]*>|\{\{.*\}\}|x{4,}|\*{4,}|\.{3,}|"
    r".*(?:your[_\-]?|my[_\-]?|example|placeholder|changeme|dummy|redacted|replace[_\-]?me|todo|sample).*|"
    r"(?:true|false|null|none|undefined))$"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip()))


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    start: int
    end: int
    value: str


def find_secrets(text: str, *, include_placeholders: bool = True) -> list[SecretMatch]:
    """Return non-overlapping secret spans, in order of appearance."""
    found: list[SecretMatch] = []
    taken: list[tuple[int, int]] = []
    for sp in SECRET_PATTERNS:
        try:
            iterator = list(sp.pattern.finditer(text, timeout=TIMEOUT))
        except TimeoutError:
            continue
        for m in iterator:
            start, end = m.span(sp.group)
            if start < 0:
                continue
            value = m.group(sp.group)
            if sp.min_entropy and shannon_entropy(value) < sp.min_entropy:
                continue
            if not include_placeholders and is_placeholder(value):
                continue
            if any(start < e and s < end for s, e in taken):
                continue
            taken.append((start, end))
            found.append(SecretMatch(sp.name, start, end, value))
    found.sort(key=lambda s: s.start)
    return found
