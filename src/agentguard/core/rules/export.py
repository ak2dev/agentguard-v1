"""Rule pack export for the website (`agentguard rules export --format json`).

Unsafe/safe examples come from the inert rule fixtures; the export includes
them only when a fixtures directory is available (repo checkout)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import regex

from ..redact import redact_snippet
from .pack import RulePack, data_dirs

MAX_EXAMPLE = 1200


_PRINTABLE = regex.compile(rb"[\x20-\x7e]{4,}")


def _example(case_dir: Path, binary: bool = False) -> dict[str, str] | None:
    """The first text file of a fixture case; for YARA rules (``binary``), the
    printable strings of the first binary file, which is what the rule matches."""
    files = sorted(
        (p for p in case_dir.rglob("*") if p.is_file() and not p.name.startswith("_") and p.name != "agentguard.lock"),
        # Sort by the POSIX string, not Path: Windows paths compare case-insensitively.
        key=lambda p: p.relative_to(case_dir).as_posix(),
    )
    if not files:
        return None
    for f in files:
        data = f.read_bytes()
        is_binary = b"\x00" in data[:4096]
        if binary and is_binary:
            strings = "\n".join(m.group(0).decode("ascii") for m in _PRINTABLE.finditer(data))
            return {"path": f.relative_to(case_dir).as_posix(),
                    "text": redact_snippet("(printable strings of a binary file)\n" + strings, MAX_EXAMPLE)}
        if binary or is_binary:
            continue
        text = data.decode("utf-8", "replace")
        return {"path": f.relative_to(case_dir).as_posix(), "text": redact_snippet(text, MAX_EXAMPLE)}
    return {"path": files[0].relative_to(case_dir).as_posix(), "text": "(binary fixture)"}


def export_rules(pack: RulePack, fixtures_dir: Path | None = None) -> dict[str, Any]:
    if fixtures_dir is None:
        rules_dir, _ = data_dirs()
        candidate = rules_dir.parent / "fixtures" / "rules"
        fixtures_dir = candidate if candidate.is_dir() else None
    rules = []
    for r in pack.rules.values():
        entry: dict[str, Any] = {
            "id": r.id,
            "version": r.version,
            "title": r.title,
            "description": r.description,
            "why": r.why,
            "severity": r.severity.value,
            "confidence": r.confidence.value,
            "remediation": r.remediation,
            "references": r.references,
            "network": r.network,
            "mappings": [m.model_dump(exclude_none=True) for m in r.mappings],
            "match_type": r.match.type,
            "examples": {},
        }
        if fixtures_dir is not None:
            for side, label in (("positive", "unsafe"), ("negative", "safe")):
                d = fixtures_dir / r.id / side
                if d.is_dir():
                    case = next((c for c in sorted(d.iterdir(), key=lambda p: p.name) if c.is_dir()), None)
                    ex = _example(case, binary=r.match.type == "yara") if case else None
                    if ex:
                        entry["examples"][label] = ex
        rules.append(entry)
    frameworks = {
        fw.framework: {"name": fw.name, "version": fw.version, "source": fw.source, "notes": fw.notes, "items": fw.items}
        for fw in pack.frameworks.values()
    }
    return {"rule_pack": {"version": pack.version, "digest": pack.digest}, "rules": rules, "frameworks": frameworks}
