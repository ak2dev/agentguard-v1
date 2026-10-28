"""Tool parameters followed into helper functions (pytaint.Resolver, code.JsResolver)."""

from agentguard.core.engine import scan
from agentguard.core.models import ScanOptions
from agentguard.core.tree import ArtifactTree

PYPROJECT = '[project]\nname = "demo-mcp"\nversion = "0.1.0"\ndependencies = ["mcp==1.9.0"]\n'
PKG = '{"name": "demo-mcp", "version": "0.1.0", "dependencies": {"@modelcontextprotocol/sdk": "1.12.0", "zod": "3.23.8"}}'
HEAD = "import os\nimport shlex\nimport subprocess\n\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('d')\n\n\n"


def _py(**files: str):
    return scan(ArtifactTree.from_mapping({"srv/pyproject.toml": PYPROJECT,
                                           **{f"srv/{k.replace('__', '/')}.py": v for k, v in files.items()}}),
                ScanOptions())


def _taint(report) -> list[tuple[str, str, str]]:
    return sorted((f.rule_id, f.confidence.value, f.message or "") for f in report.findings
                  if f.rule_id in ("AG-CODE-001", "AG-CODE-002", "AG-CODE-003", "AG-CODE-006"))


def test_keyword_argument_reaches_helper_sink():
    out = _taint(_py(server=HEAD + "def sh(*, line):\n    return os.system(line)\n\n\n"
                     "@mcp.tool()\ndef t(x: str):\n    return sh(line='echo ' + x)\n"))
    assert [(r, c) for r, c, _ in out] == [("AG-CODE-001", "high")]
    assert "os.system in sh(), srv/server.py:11" in out[0][2]


def test_untainted_parameter_of_helper_is_not_reported():
    out = _taint(_py(server=HEAD + "def sh(prefix, line):\n    return os.system(line)\n\n\n"
                     "@mcp.tool()\ndef t(x: str):\n    return sh(x, 'uptime')\n"))
    assert out == []


def test_sanitizer_in_helper_lowers_confidence():
    out = _taint(_py(server=HEAD + "def sh(line):\n    return os.system('ls ' + shlex.quote(line))\n\n\n"
                     "@mcp.tool()\ndef t(x: str):\n    return sh(x)\n"))
    assert [(r, c) for r, c, _ in out] == [("AG-CODE-001", "medium")]


def test_self_method_in_same_class():
    out = _taint(_py(server=HEAD + "class Tools:\n    def _run(self, line):\n        return os.system(line)\n\n"
                     "    @mcp.tool()\n    def t(self, x: str):\n        return self._run(x)\n"))
    assert [r for r, _, _ in out] == ["AG-CODE-001"]


def test_recursion_terminates_and_depth_is_bounded():
    recursive = _py(server=HEAD + "def a(v, n=0):\n    return a(v, n + 1) if n < 3 else os.system(v)\n\n\n"
                    "@mcp.tool()\ndef t(x: str):\n    return a(x)\n")
    assert [r for r, _, _ in _taint(recursive)] == ["AG-CODE-001"]
    chain = "".join(f"def h{i}(v):\n    return h{i + 1}(v)\n\n\n" for i in range(1, 5))
    deep = _py(server=HEAD + chain + "def h5(v):\n    return os.system(v)\n\n\n"
               "@mcp.tool()\ndef t(x: str):\n    return h1(x)\n")
    assert _taint(deep) == []  # five helpers deep: beyond MAX_DEPTH (3)


def test_package_imports_and_installed_packages():
    found = _taint(_py(pkg____init__="", pkg__shell="import os\n\ndef run(c):\n    return os.system(c)\n",
                       pkg__server=HEAD + "from pkg.shell import run\n\n\n@mcp.tool()\ndef t(x: str):\n    return run(x)\n"))
    assert [r for r, _, _ in found] == ["AG-CODE-001"]
    missing = _taint(_py(server=HEAD + "from somepkg.shell import run\n\n\n@mcp.tool()\ndef t(x: str):\n    return run(x)\n"))
    assert missing == []  # not in the component: not followed


def test_js_require_destructured_and_arrow_expression_body():
    tree = ArtifactTree.from_mapping({
        "srv/package.json": PKG,
        "srv/src/lib.js": "const { execSync } = require('child_process');\n"
                          "const fetchIt = (u) => fetch(u);\nfunction run(c) {\n  return execSync(c);\n}\n"
                          "module.exports = { run, fetchIt };\n",
        "srv/src/index.js": "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
                            "const { z } = require('zod');\nconst { run, fetchIt } = require('./lib');\n"
                            "const server = new McpServer({ name: 'd', version: '0.1.0' });\n"
                            "server.tool('t', 'T.', { q: z.string() }, async ({ q }) => {\n"
                            "  run('grep ' + q);\n  return { content: [{ type: 'text', text: await fetchIt(q) }] };\n});\n",
    })
    out = _taint(scan(tree, ScanOptions()))
    assert [r for r, _, _ in out] == ["AG-CODE-001", "AG-CODE-006"]
    assert "execSync in run(), srv/src/lib.js:4" in out[0][2]


def _ts(helper: str, call: str):
    tree = ArtifactTree.from_mapping({
        "srv/package.json": PKG,
        "srv/src/lib.ts": helper,
        "srv/src/index.ts": "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nimport { z } from 'zod';\n"
                            "import { get } from './lib.js';\n"
                            "const server = new McpServer({ name: 'd', version: '0.1.0' });\n"
                            "server.tool('t', 'T.', { q: z.string() }, async ({ q }) => ({\n"
                            f"  content: [{{ type: 'text', text: await {call} }}],\n}}));\n",
    })
    return [r for r, _, _ in _taint(scan(tree, ScanOptions()))]


def test_js_fixed_host_and_strings_and_generics():
    fixed = ("const BASE = 'https://api.example.invalid';\n"
             "export async function get(path: string, params: Record<string, unknown> = {}, raw = false) {\n"
             "  const url = new URL(`${BASE}${path}`);\n  return fetch(url.toString());\n}\n")
    assert _ts(fixed, "get(`/items/${q}`)") == []            # input only reaches the path
    assert _ts(fixed, "get('/items', { q }, true)") == []     # third argument maps to 'raw', not past a generic
    open_url = "export async function get(target: string) {\n  return fetch(target);\n}\n"
    assert _ts(open_url, "get(q)") == ["AG-CODE-006"]
    assert _ts(open_url, "get('/q/items')") == []             # 'q' inside a string is text
    assert _ts(open_url, "get(`${q}/items`)") == ["AG-CODE-006"]
