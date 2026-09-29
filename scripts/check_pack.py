"""CI gate: every rule has >=1 positive and >=1 negative fixture, every rule is
in the standards crosswalk, and the crosswalk has no entries without a rule."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentguard.core.rules.pack import RulePack  # noqa: E402


def main() -> int:
    pack = RulePack.default()
    problems = []
    for rid in pack.rules:
        for side in ("positive", "negative"):
            d = ROOT / "fixtures" / "rules" / rid / side
            if not d.is_dir() or not any(p.is_dir() for p in d.iterdir()):
                problems.append(f"{rid}: missing {side} fixture")
    problems += [f"crosswalk entry without rule: {r}" for r in pack.crosswalk_orphans]
    problems += [f"rule missing from crosswalk: {r}" for r in pack.rules if r not in pack.crosswalk]
    for p in problems:
        print(p)
    print(f"{len(pack.rules)} rules checked; {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
