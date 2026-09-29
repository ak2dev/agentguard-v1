"""Bootstrap fixtures for the LLM-judge rules using *recorded* verdicts, so the
rules are testable offline and deterministically (provenance only)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentguard.core.inventory import build_inventory  # noqa: E402
from agentguard.core.tree import ArtifactTree  # noqa: E402

FIX = ROOT / "fixtures" / "rules"
SKILL = {
    "csv-tool/SKILL.md": "---\nname: csv-tool\ndescription: Summarize CSV files.\n---\nRun scripts/stats.py on the file.\n",
    "csv-tool/scripts/stats.py": "import csv, sys\nrows = list(csv.reader(open(sys.argv[1])))\nprint(len(rows))\n",
}


def comp_id(files: dict[str, str]) -> str:
    inv = build_inventory(ArtifactTree.from_mapping(files))
    return next(c.id for c in inv.components.values() if c.kind.value == "skill")


def result(kind: str, cid: str, path: str, verdict: dict) -> dict:
    return {"kind": kind, "component_id": cid, "path": path, "content_hash": "0" * 64,
            "provider": "recorded", "model": "fixture", "verdict": verdict}


CID = comp_id(SKILL)
MISMATCH = {"mismatch": True, "undisclosed_behaviors": ["uploads the CSV to a remote host"], "confidence": "medium",
            "explanation": "The description only mentions summarizing; the script also sends data out.",
            "quotes": [{"text": "print(len(rows))"}]}
NO_MISMATCH = {**MISMATCH, "mismatch": False, "undisclosed_behaviors": [], "explanation": "Behavior matches the description."}
MANIP = {"manipulation": True, "techniques": ["concealment"], "confidence": "high",
         "explanation": "Asks the agent to keep an action from the user in paraphrased form.",
         "quotes": [{"text": "Run scripts/stats.py on the file."}]}
NO_MANIP = {**MANIP, "manipulation": False, "techniques": [], "explanation": "Ordinary task instructions."}

CASES = {
    ("AG-LLM-001", "positive", "judge-mismatch"): [result("mismatch", CID, "csv-tool/scripts/stats.py", MISMATCH)],
    ("AG-LLM-001", "negative", "judge-consistent"): [result("mismatch", CID, "csv-tool/scripts/stats.py", NO_MISMATCH)],
    ("AG-LLM-002", "positive", "judge-manipulation"): [result("manipulation", CID, "csv-tool/SKILL.md", MANIP)],
    ("AG-LLM-002", "negative", "judge-clean"): [result("manipulation", CID, "csv-tool/SKILL.md", NO_MANIP)],
}


def main() -> None:
    for r in ("AG-LLM-001", "AG-LLM-002"):
        shutil.rmtree(FIX / r, ignore_errors=True)
    for (rule, side, case), results in CASES.items():
        base = FIX / rule / side / case
        for rel, content in SKILL.items():
            p = base / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content.encode("utf-8"))
        cfg = {"network": {"llm_judge": True}, "judge_results": results}
        (base / "_case.yaml").write_bytes(json.dumps(cfg, indent=2).encode("utf-8"))
    print("wrote fixtures for 2 rules")


if __name__ == "__main__":
    main()
