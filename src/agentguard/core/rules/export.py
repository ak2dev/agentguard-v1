"""Rule pack export for the website (`agentguard rules export --format json`).

Unsafe/safe examples come from the inert rule fixtures; the export includes
them only when a fixtures directory is available (repo checkout)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..redact import redact_snippet
from .pack import RulePack, data_dirs

MAX_EXAMPLE = 1200


def _example(case_dir: Path) -> dict[str, str] | None:
    files = sorted(p for p in case_dir.rglob("*") if p.is_file() and not p.name.startswith("_") and p.name != "agentguard.lock")
    if not files:
        return None
    for f in files:
        data = f.read_bytes()
        if b"\x00" in data[:4096]:
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
                    case = next((c for c in sorted(d.iterdir()) if c.is_dir()), None)
                    ex = _example(case) if case else None
                    if ex:
                        entry["examples"][label] = ex
        rules.append(entry)
    frameworks = {
        fw.framework: {"name": fw.name, "version": fw.version, "source": fw.source, "notes": fw.notes, "items": fw.items}
        for fw in pack.frameworks.values()
    }
    return {"rule_pack": {"version": pack.version, "digest": pack.digest}, "rules": rules, "frameworks": frameworks}
