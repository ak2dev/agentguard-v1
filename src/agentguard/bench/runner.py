"""`agentguard bench`: precision / recall / F1 / FPR per category and severity.

Item-level metrics. For a severity threshold T, an item is *flagged* when it
has at least one finding with severity >= T (AG-SYS-* coverage findings are
ignored). Malicious and adversarial items are positives; benign items are
negatives.

    precision = TP / (TP + FP)      recall = TP / (TP + FN)
    FPR       = FP / (FP + TN)      F1     = 2PR / (P + R)

Severity-calibrated recall: every malicious and adversarial item records the
severity its attack warrants (``expected_severity``, set when the item is
written). An item *meets* it when its highest finding is at least that severe.
Raw recall at CRITICAL counts every positive, including items that a correct
scanner should report at HIGH (shadowing, side channels, wording-only
manipulation); ``critical_expected`` restricts it to items that warrant CRITICAL.

Also reported: per-category recall and FPR, per-rule benign hits (the rules
responsible for false positives), whether an item's *expected* rules fired,
and scan performance.
"""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.archive import from_archive
from ..core.engine import ENGINE_VERSION, scan
from ..core.models import Lockfile, Report, ScanOptions
from ..core.models.enums import Severity
from ..core.parsers.safe_yaml import safe_load
from ..core.rules.pack import RulePack
from ..io.fs_loader import load_path

THRESHOLDS = (Severity.critical, Severity.high, Severity.medium)
# Coverage and configuration-posture findings are not verdicts about an item;
# flows are reported separately (flow_findings) instead of counting as detections.
_NOT_COMPONENT_RULES = ("AG-SYS-", "AG-FLOW-", "AG-POL-")
TARGETS = {"precision_critical": 0.95, "precision_high": 0.85, "fpr_high_max": 0.02}


@dataclass
class Item:
    id: str
    label: str            # benign | malicious | adversarial
    category: str
    split: str            # dev | heldout
    path: Path
    source: str = "synthetic"
    author: str = ""
    expected_rules: list[str] = field(default_factory=list)
    expected_severity: Severity | None = None
    notes: str = ""


def load_manifest(root: Path) -> list[Item]:
    res = safe_load((root / "manifest.yaml").read_text(encoding="utf-8"), max_nodes=500_000)
    if res.error:
        raise ValueError(f"bench manifest: {res.error}")
    items = []
    for raw in (res.value or {}).get("items", []):
        items.append(Item(
            id=raw["id"], label=raw["label"], category=raw["category"], split=raw.get("split", "dev"),
            path=root / "corpus" / raw["path"], source=raw.get("source", "synthetic"), author=raw.get("author", ""),
            expected_rules=list(raw.get("expected_rules", [])), notes=raw.get("notes", ""),
            expected_severity=Severity(raw["expected_severity"]) if raw.get("expected_severity") else None,
        ))
    return items


def _scan_item(item: Item, pack: RulePack) -> Report:
    opts: dict[str, Any] = {}
    lock = item.path / "agentguard.lock"
    if lock.exists():
        opts["lock"] = Lockfile.model_validate_json(lock.read_text(encoding="utf-8"))
    archive = item.path / "_archive.zip"
    tree = from_archive(archive.read_bytes()) if archive.exists() else load_path(item.path)
    tree.files.pop("agentguard.lock", None)
    return scan(tree, ScanOptions(**opts), pack)


def _flag(report: Report, t: Severity) -> bool:
    return any(f.severity.at_least(t) for f in report.findings if not f.rule_id.startswith(_NOT_COMPONENT_RULES))


def _ratio(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def _metrics(rows: list[dict[str, Any]], t: Severity) -> dict[str, Any]:
    tp = sum(1 for r in rows if r["positive"] and r["flags"][t.value])
    fn = sum(1 for r in rows if r["positive"] and not r["flags"][t.value])
    fp = sum(1 for r in rows if not r["positive"] and r["flags"][t.value])
    tn = sum(1 for r in rows if not r["positive"] and not r["flags"][t.value])
    p, rc = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * p * rc / (p + rc), 4) if p and rc else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": rc, "f1": f1, "fpr": _ratio(fp, fp + tn)}


def _calibrated(rows: list[dict[str, Any]]) -> dict[str, Any]:
    pos = [r for r in rows if r["positive"] and r["expected_severity"] is not None]
    crit = [r for r in pos if r["expected_severity"] is Severity.critical]
    met = sum(1 for r in pos if r["severity_met"])
    crit_tp = sum(1 for r in crit if r["flags"][Severity.critical.value])
    return {"items": len(pos), "severity_met": met, "severity_met_rate": _ratio(met, len(pos)),
            "critical_expected": {"items": len(crit), "tp": crit_tp, "recall": _ratio(crit_tp, len(crit))},
            "below_expected": sorted(r["id"] for r in pos if not r["severity_met"])}


def run_bench(root: Path, split: str = "all", pack: RulePack | None = None) -> dict[str, Any]:
    pack = pack or RulePack.default()
    items = [i for i in load_manifest(root) if split == "all" or i.split == split]
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    for item in items:
        t0 = time.perf_counter()
        report = _scan_item(item, pack)
        fired = sorted({f.rule_id for f in report.findings})
        top = max((f.severity for f in report.findings if not f.rule_id.startswith(_NOT_COMPONENT_RULES)),
                  key=lambda s: s.rank, default=None)
        rows.append({
            "id": item.id, "label": item.label, "category": item.category, "split": item.split, "source": item.source,
            "positive": item.label != "benign",
            "flags": {t.value: _flag(report, t) for t in THRESHOLDS},
            "max_severity": top,
            "expected_severity": item.expected_severity,
            "severity_met": (None if item.expected_severity is None
                             else top is not None and top.rank >= item.expected_severity.rank),
            "rules": fired,
            "expected_hit": (not item.expected_rules) or bool(set(item.expected_rules) & set(fired)),
            "benign_hits": [f"{f.rule_id}:{f.severity.value}" for f in report.findings if item.label == "benign"
                            and f.severity.rank >= Severity.medium.rank and not f.rule_id.startswith(_NOT_COMPONENT_RULES)],
            "flow_findings": sorted({f"{f.rule_id}:{f.severity.value}" for f in report.findings if f.rule_id.startswith("AG-FLOW-")}),
            "ms": round((time.perf_counter() - t0) * 1000, 1),
        })
    elapsed = time.perf_counter() - started

    overall = {t.value: _metrics(rows, t) for t in THRESHOLDS}
    by_split = {s: {t.value: _metrics([r for r in rows if r["split"] == s], t) for t in THRESHOLDS}
                for s in sorted({r["split"] for r in rows})}
    categories: dict[str, Any] = {}
    for cat in sorted({r["category"] for r in rows}):
        sub = [r for r in rows if r["category"] == cat]
        pos = sub[0]["positive"]
        entry: dict[str, Any] = {"label": sub[0]["label"], "items": len(sub)}
        for t in THRESHOLDS:
            flagged = sum(1 for r in sub if r["flags"][t.value])
            entry[f"{'recall' if pos else 'fpr'}_{t.value}"] = _ratio(flagged, len(sub))
        if pos:
            entry["expected_rule_hit_rate"] = _ratio(sum(1 for r in sub if r["expected_hit"]), len(sub))
            entry["severity_met_rate"] = _ratio(sum(1 for r in sub if r["severity_met"]), len(sub))
        categories[cat] = entry
    rule_fp: dict[str, int] = {}
    for r in rows:
        for hit in set(r["benign_hits"]):
            rule_fp[hit] = rule_fp.get(hit, 0) + 1
    crit, high = overall["critical"], overall["high"]
    targets = {
        "precision_critical": {"target": TARGETS["precision_critical"], "actual": crit["precision"],
                               "met": crit["precision"] is not None and crit["precision"] >= TARGETS["precision_critical"]},
        "precision_high": {"target": TARGETS["precision_high"], "actual": high["precision"],
                           "met": high["precision"] is not None and high["precision"] >= TARGETS["precision_high"]},
        "fpr_high_max": {"target": TARGETS["fpr_high_max"], "actual": high["fpr"],
                         "met": high["fpr"] is not None and high["fpr"] <= TARGETS["fpr_high_max"]},
    }
    counts = {lbl: sum(1 for r in rows if r["label"] == lbl) for lbl in ("benign", "malicious", "adversarial")}
    sources = {s: sum(1 for r in rows if r["source"] == s) for s in sorted({r["source"] for r in rows})}
    return {
        "schema": "agentguard-bench/1",
        "engine_version": ENGINE_VERSION,
        "rule_pack": {"version": pack.version, "digest": pack.digest},
        "date": dt.date.today().isoformat(),
        "split": split,
        "corpus": {"items": len(rows), **counts, "sources": sources},
        "overall": overall,
        "by_split": by_split,
        "calibrated": {"overall": _calibrated(rows),
                       "by_split": {s: _calibrated([r for r in rows if r["split"] == s]) for s in sorted({r["split"] for r in rows})}},
        "categories": categories,
        "benign_hits_by_rule": dict(sorted(rule_fp.items(), key=lambda kv: (-kv[1], kv[0]))),
        "targets": targets,
        "performance": {"total_seconds": round(elapsed, 3), "mean_ms_per_item": round(elapsed * 1000 / max(1, len(rows)), 1)},
        "items": rows,
    }


def perf_check(n_skills: int = 100, n_configs: int = 20) -> dict[str, Any]:
    """Static scan of N skills + M server configs in one tree (spec: < 10 s)."""
    from ..core.tree import ArtifactTree

    files: dict[str, str] = {}
    for i in range(n_skills):
        files[f"skills/skill-{i:03d}/SKILL.md"] = (
            f"---\nname: skill-{i:03d}\ndescription: Summarize report number {i} and list key metrics.\n"
            "allowed-tools: Read Bash(git status:*)\n---\n# Report summarizer\n\n"
            + "Read the report, extract headings, and summarize each section in two sentences.\n" * 40
            + "Run `python scripts/summarize.py report.md` to produce a draft.\n"
        )
        files[f"skills/skill-{i:03d}/scripts/summarize.py"] = (
            "import sys, pathlib\n\n\ndef main(p):\n    text = pathlib.Path(p).read_text()\n"
            "    return [l for l in text.splitlines() if l.startswith('#')]\n\n\nif __name__ == '__main__':\n"
            "    print(main(sys.argv[1]))\n" * 5
        )
    import json

    for j in range(n_configs):
        files[f"configs/c{j:02d}/.mcp.json"] = json.dumps({"mcpServers": {
            f"srv{j}-{k}": {"command": "npx", "args": ["-y", f"@example/server-{k}@1.{j}.{k}"]} for k in range(3)}})
    tree = ArtifactTree.from_mapping(files)
    t0 = time.perf_counter()
    report = scan(tree, ScanOptions())
    secs = time.perf_counter() - t0
    return {"skills": n_skills, "configs": n_configs, "seconds": round(secs, 3), "target_seconds": 10,
            "met": secs < 10, "findings": len(report.findings)}
