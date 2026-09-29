"""One-off bootstrap: build mappings/crosswalk.yaml from the approved design
table (docs/design/v1-design.md). After bootstrap the crosswalk is maintained
by hand; this script is kept for provenance only."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
design = (root / "docs/design/v1-design.md").read_text(encoding="utf-8")
rows = [line for line in design.splitlines() if line.startswith("| AG-")]
out = [
    "# Rule -> standards crosswalk. [] = not applicable, null = pending review (TODO).",
    "# Framework ids must exist in mappings/<framework>.yaml.",
    "",
]


def ids(value: str, suffix: str = "") -> str:
    if value in ("—", "", "-", "per advisory"):
        return "[]"
    # Quoted: libyaml rejects a ':' inside a plain scalar in a flow sequence (e.g. LLM01:2025).
    return "[" + ", ".join(f'"{x.strip()}{suffix}"' for x in value.split(",")) + "]"


for row in rows:
    cells = [c.strip() for c in row.replace("\\|", "/").split("|")[1:-1]]
    rid, asi, mcp, ast, llm, cwe = cells[0], cells[4], cells[5], cells[6], cells[7], cells[8]
    out += [
        f"{rid}:",
        f"  owasp-asi-2026: {ids(asi)}",
        f"  owasp-mcp-2025-beta: {ids(mcp, ':2025')}",
        f"  owasp-ast-1.0: {ids(ast)}",
        f"  owasp-llm-2025: {ids(llm, ':2025')}",
        "  nsa-csi-mcp-2026-05: null",
        f"  cwe: {ids(cwe)}",
    ]
(root / "mappings/crosswalk.yaml").write_text("\n".join(out) + "\n", encoding="utf-8")
print(len(rows), "rows")
