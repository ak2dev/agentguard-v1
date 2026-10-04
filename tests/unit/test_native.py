"""Optional native analyzers: YARA (``yara``) and tree-sitter (``code.ts``).

Rule behaviour is covered by fixtures (``requires:`` in _case.yaml); these
tests cover the plumbing around them."""

from __future__ import annotations

import json

import pytest

from agentguard import ArtifactTree, ScanOptions, scan
from agentguard.core import engine
from agentguard.core.rules.pack import RulePack, RulePackError

PACK = RulePack.default()


def _with_yara_rule(rule_file: str) -> dict[str, bytes]:
    from agentguard.core.rules.pack import data_dirs

    rules_dir, mappings_dir = data_dirs()
    files = {f"rules/{p.relative_to(rules_dir).as_posix()}": p.read_bytes() for p in rules_dir.rglob("*") if p.is_file()}
    files.update({f"mappings/{p.relative_to(mappings_dir).as_posix()}": p.read_bytes() for p in mappings_dir.rglob("*") if p.is_file()})
    text = files["rules/skill/structure.yaml"].decode()
    files["rules/skill/structure.yaml"] = text.replace("rules/yara/bundled-stager.yar", rule_file).encode()
    return files


def test_yara_rule_file_must_exist():
    with pytest.raises(RulePackError, match="YARA rule file rules/yara/missing.yar not found"):
        RulePack.from_files(_with_yara_rule("rules/yara/missing.yar"))


def test_every_yara_source_compiles_and_names_its_rule():
    yara = pytest.importorskip("yara")
    from agentguard.core.analyzers.yara_rules import compile_pack

    assert PACK.yara_sources, "rule pack ships no YARA sources"
    compile_pack(PACK)
    owners = {r.match.rule_file: r.id for r in PACK.rules.values() if r.match.type == "yara"}
    for path, source in PACK.yara_sources.items():
        assert path in owners, f"{path} is not referenced by any rule"
        compiled = list(yara.compile(source=source, includes=False))
        assert compiled, f"{path} defines no YARA rules"
        for y in compiled:
            assert y.meta.get("agentguard_rule") == owners[path], f"{path}: {y.identifier} meta names the wrong rule"


def test_native_analyzers_reported_skipped_when_missing(monkeypatch):
    monkeypatch.setattr(engine, "native_available", lambda cls: False)
    report = scan(ArtifactTree.from_mapping({"x/SKILL.md": "---\nname: x\ndescription: X.\n---\n"}), ScanOptions())
    runs = {r.id: r for r in report.analyzers}
    for aid in ("code.ts", "yara"):
        assert runs[aid].status == "skipped" and "native" in (runs[aid].reason or "")
    # Skipped YARA rules are not counted as evaluated.
    yara_rules = sum(1 for r in PACK.rules.values() if r.match.type == "yara")
    full = scan(ArtifactTree.from_mapping({"x/SKILL.md": "---\nname: x\ndescription: X.\n---\n"}), ScanOptions())
    if {r.id: r.status for r in full.analyzers}["yara"] == "ran":
        assert full.stats.rules_evaluated == report.stats.rules_evaluated + yara_rules


PKG = json.dumps({"name": "demo", "version": "0.1.0", "dependencies": {"@modelcontextprotocol/sdk": "1.12.0"}})


def _ts_server(body: str, header: str = "") -> ArtifactTree:
    src = ("import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nimport { z } from 'zod';\n" + header +
           "const server = new McpServer({ name: 'demo', version: '0.1.0' });\n" + body)
    return ArtifactTree.from_mapping({"server/package.json": PKG, "server/src/index.ts": src})


def _ts_only(tree: ArtifactTree):
    """Run only the tool extraction and the tree-sitter analyzer."""
    return scan(tree, ScanOptions(analyzers={"mcp.units", "code.ts"}))


def test_treesitter_offsets_survive_non_ascii():
    pytest.importorskip("tree_sitter")
    tree = _ts_server(
        "// ünïcödé 🚀 comment before the handler\n"
        "server.tool('run', 'Run 🚀 a thing', { cmd: z.string() }, async ({ cmd }) => {\n"
        "  const label = 'naïve 🚀';\n  execSync(`${label} ${cmd}`);\n  return { content: [] };\n});\n",
        "import { execSync } from 'node:child_process';\n",
    )
    hits = [f for f in _ts_only(tree).findings if f.rule_id == "AG-CODE-001"]
    assert len(hits) == 1
    src = tree.files["server/src/index.ts"].data.decode()
    line = src.splitlines()[hits[0].primary.start_line - 1]
    assert line.strip().startswith("execSync(")


def test_treesitter_regexp_exec_is_not_a_shell():
    pytest.importorskip("tree_sitter")
    tree = _ts_server(
        "server.tool('match', 'Match a pattern.', { text: z.string() }, async ({ text }) => {\n"
        "  const m = /id=(\\d+)/.exec(text);\n  return { content: [{ type: 'text', text: m ? m[1] : '' }] };\n});\n",
    )
    assert not [f for f in _ts_only(tree).findings if f.rule_id.startswith("AG-CODE-00")]


def test_treesitter_unimported_exec_is_not_child_process():
    # A local function named exec is not child_process.exec.
    pytest.importorskip("tree_sitter")
    tree = _ts_server(
        "function exec(q) { return db.prepare(q); }\n"
        "server.tool('find', 'Find rows.', { name: z.string() }, async ({ name }) => {\n"
        "  exec(name);\n  return { content: [] };\n});\n",
    )
    assert not [f for f in _ts_only(tree).findings if f.rule_id == "AG-CODE-001"]


def test_treesitter_url_needs_control_of_the_start():
    pytest.importorskip("tree_sitter")
    fixed = _ts_server("server.tool('get', 'Get an item.', { id: z.string() }, async ({ id }) => {\n"
                       "  const url = `https://api.example.invalid/items/${id}`;\n  await fetch(url);\n  return { content: [] };\n});\n")
    open_ = _ts_server("server.tool('get', 'Fetch a page.', { base: z.string() }, async ({ base }) => {\n"
                       "  const url = `${base}/items`;\n  await fetch(url);\n  return { content: [] };\n});\n")
    assert not [f for f in _ts_only(fixed).findings if f.rule_id == "AG-CODE-006"]
    assert [f for f in _ts_only(open_).findings if f.rule_id == "AG-CODE-006"]
