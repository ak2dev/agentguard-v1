"""CI gate: the benchmark must meet its v1 targets and must not regress
against the committed results (precision/FPR at critical and high, and
per-category recall) by more than a small tolerance."""

from __future__ import annotations

import json
import sys

TOL = 0.02


def main(new_path: str, old_path: str) -> int:
    new = json.load(open(new_path, encoding="utf-8"))
    old = json.load(open(old_path, encoding="utf-8"))
    problems = []
    for name, t in new["targets"].items():
        if not t["met"]:
            problems.append(f"target {name} not met: {t['actual']} vs {t['target']}")
    for sev in ("critical", "high"):
        n, o = new["overall"][sev], old["overall"][sev]
        if n["precision"] is not None and o["precision"] is not None and n["precision"] < o["precision"] - TOL:
            problems.append(f"precision@{sev} regressed {o['precision']} -> {n['precision']}")
        if n["fpr"] is not None and o["fpr"] is not None and n["fpr"] > o["fpr"] + TOL:
            problems.append(f"FPR@{sev} regressed {o['fpr']} -> {n['fpr']}")
    for cat, e in new["categories"].items():
        prev = old["categories"].get(cat)
        if prev and "recall_high" in e and e["recall_high"] is not None and prev.get("recall_high") is not None:
            if e["recall_high"] < prev["recall_high"] - TOL:
                problems.append(f"recall@high for {cat} regressed {prev['recall_high']} -> {e['recall_high']}")
    for p in problems:
        print(p)
    print("benchmark OK" if not problems else f"{len(problems)} benchmark problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
