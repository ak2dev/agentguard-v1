"""Generate everything the website shows from source (CI fails if stale):

* site/src/data/generated/rules.json      ← `agentguard rules export` (rule YAML + inert fixtures)
* site/src/data/generated/coverage.json   ← mappings/*.yaml + crosswalk (gaps included)
* site/src/data/generated/cli.json        ← the Typer app itself
* site/src/data/generated/bench.json      ← bench/results/latest.json
* site/public/sample-report.html          ← a real report of a synthetic malicious fixture
* schemas/*.json                          ← Pydantic models
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import typer  # noqa: E402

from agentguard import __version__  # noqa: E402
from agentguard.cli.app import app  # noqa: E402
from agentguard.core.engine import ENGINE_VERSION, scan  # noqa: E402
from agentguard.core.models import ScanOptions  # noqa: E402
from agentguard.core.report.html import render_html  # noqa: E402
from agentguard.core.rules.export import export_rules  # noqa: E402
from agentguard.core.rules.pack import RulePack  # noqa: E402
from agentguard.core.schemas import SCHEMAS  # noqa: E402
from agentguard.io.fs_loader import load_path  # noqa: E402

OUT = ROOT / "site" / "src" / "data" / "generated"
SAMPLE_FIXTURE = ROOT / "bench" / "corpus" / "malicious" / "envdump-python"


def write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = data if isinstance(data, str) else json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    path.write_bytes(text.encode("utf-8"))


def cli_reference() -> dict:
    cmd = typer.main.get_command(app)

    def describe(c, path: list[str]) -> list[dict]:  # Typer vendors click; use duck typing
        entry = {
            "name": " ".join(path),
            "help": (c.help or "").strip(),
            "params": [
                {
                    "name": p.name,
                    "kind": "argument" if "Argument" in type(p).__name__ else "option",
                    "opts": list(getattr(p, "opts", [])),
                    "help": (getattr(p, "help", "") or "").strip(),
                    "default": None if p.default in (None, ()) or callable(p.default) else str(p.default),
                    "required": bool(p.required),
                }
                for p in c.params if p.name not in ("help",)
            ],
        }
        out = [entry] if path else []
        if hasattr(c, "commands"):
            for name in sorted(c.commands):
                out += describe(c.commands[name], [*path, name])
        return out

    return {"program": "agentguard", "version": __version__, "commands": describe(cmd, [])}


def coverage(pack: RulePack) -> dict:
    frameworks = []
    for fw in ("owasp-asi-2026", "owasp-mcp-2025-beta", "owasp-ast-1.0", "owasp-llm-2025", "nsa-csi-mcp-2026-05", "cwe"):
        cat = pack.frameworks.get(fw)
        items = []
        for iid, title in (cat.items.items() if cat else []):
            rules = sorted(r.id for r in pack.rules.values() if any(m.framework == fw and m.id == iid for m in r.mappings))
            items.append({"id": iid, "title": title, "rules": rules})
        todo = sorted(r.id for r in pack.rules.values() if any(m.framework == fw and m.id is None for m in r.mappings))
        frameworks.append({
            "framework": fw, "name": cat.name if cat else fw, "version": cat.version if cat else "",
            "source": cat.source if cat else "", "notes": cat.notes if cat else "",
            "items": items, "rules_pending_mapping": todo,
            "gaps": [i["id"] for i in items if not i["rules"]],
        })
    return {"rule_pack": pack.version, "frameworks": frameworks}


def main() -> None:
    pack = RulePack.default()
    write(OUT / "rules.json", export_rules(pack))
    write(OUT / "coverage.json", coverage(pack))
    write(OUT / "cli.json", cli_reference())
    bench_src = ROOT / "bench" / "results" / "latest.json"
    if bench_src.exists():
        bench = json.loads(bench_src.read_text(encoding="utf-8"))
        bench.pop("items", None)
        write(OUT / "bench.json", bench)
    write(OUT / "meta.json", {"engine_version": ENGINE_VERSION, "package_version": __version__,
                              "rule_pack": pack.version, "rule_count": len(pack.rules)})
    report = scan(load_path(SAMPLE_FIXTURE), ScanOptions())
    write(ROOT / "site" / "public" / "sample-report.html", render_html(report))
    for name, build in SCHEMAS.items():
        write(ROOT / "schemas" / f"{name}.v1.json", build())
    print(f"site data: {len(pack.rules)} rules, sample report with {len(report.findings)} findings")


if __name__ == "__main__":
    main()
