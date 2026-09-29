"""Code analyzer (AG-CODE-*, plus code-backed AG-MCP-META-011/012/020).

* Python tool handlers: real intra-procedural taint via ``ast`` (pytaint).
* JS/TS tool handlers: sink calls are located and their argument lists
  extracted by bracket matching; a handler parameter appearing directly in a
  sink's arguments is a high-confidence hit. (The optional tree-sitter
  analyzer adds full data-flow when installed.)
* Capability evidence regardless of taint for server source and bundled
  skill scripts.
"""

from __future__ import annotations

import ast
import json
import urllib.parse
from dataclasses import dataclass
from typing import ClassVar

import regex

from ..artifacts import ArtifactText
from ..models import Component, Span, ToolDef
from ..models.enums import ArtifactRole, CapLabel, ComponentKind, Confidence, EvidenceKind, Severity
from ..textutil import TIMEOUT
from . import pytaint
from .base import Context
from .envcopy import env_dumps
from .heuristics import CREDENTIAL_PATH, EGRESS_CODE, PERSISTENCE, finditer, search
from .mcp import ToolHandler

TAINT_RULE = {
    "shell": "AG-CODE-001", "argv": "AG-CODE-002", "eval": "AG-CODE-003", "deser": "AG-CODE-004",
    "path": "AG-CODE-005", "url": "AG-CODE-006", "sql": "AG-CODE-007", "template": "AG-CODE-008",
}
TAINT_TEXT = {
    "shell": "reaches a shell command", "argv": "is passed as a process argument", "eval": "reaches eval/exec",
    "deser": "is deserialized unsafely", "path": "is used as a filesystem path", "url": "controls an outbound request URL",
    "sql": "is concatenated into SQL", "template": "is compiled as a template",
}
TAINT_LABEL = {
    "shell": CapLabel.code_exec, "argv": CapLabel.code_exec, "eval": CapLabel.code_exec, "deser": CapLabel.code_exec,
    "path": CapLabel.reads_private_data, "url": CapLabel.external_egress, "sql": CapLabel.reads_private_data,
    "template": CapLabel.code_exec,
}

# ---- JS/TS sink shapes (call name → kind) -----------------------------------
_JS_SINKS = (
    (regex.compile(r"\b(?:child_process\.|cp\.)?(?:exec|execSync)\s*\("), "shell"),
    (regex.compile(r"\b(?:spawn|spawnSync|execFile|execFileSync|execa|execaSync|fork)\s*\("), "argv"),
    (regex.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\("), "eval"),
    (regex.compile(r"\b(?:unserialize|deserialize)\s*\("), "deser"),
    (regex.compile(r"\bfs(?:\.promises)?\.(?:readFile|writeFile|appendFile|unlink|rm|rmdir|readdir|createReadStream|createWriteStream|"
                   r"readFileSync|writeFileSync|appendFileSync|unlinkSync|rmSync|readdirSync|copyFile|rename)\w*\s*\(|"
                   r"\b(?:readFile|writeFile|readFileSync|writeFileSync)\s*\("), "path"),
    (regex.compile(r"\b(?:fetch|got|ky|axios(?:\.(?:get|post|put|patch|delete|request))?|https?\.(?:get|request)|undici\.request)\s*\("), "url"),
    (regex.compile(r"\.(?:query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\("), "sql"),
    (regex.compile(r"\b(?:ejs|Handlebars|handlebars|pug|nunjucks|_)\.(?:render|compile|renderString|template)\s*\("), "template"),
)
_JS_PARAMS = regex.compile(r"(?:async\s*)?(?:function\s*\w*\s*)?\(\s*(\{[^}]{0,400}\}|[A-Za-z_$][\w$]*)\s*(?::[^)]{0,200})?\)\s*(?:=>|\{)")


def _call_args(text: str, open_idx: int, limit: int = 4000) -> str:
    depth = 0
    i = open_idx
    end = min(len(text), open_idx + limit)
    in_str: str | None = None
    while i < end:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            elif in_str == "`" and ch == "$" and i + 1 < end and text[i + 1] == "{":
                pass
        elif ch == "/" and text.startswith("//", i):
            nl = text.find("\n", i)                           # comment: skip, quotes in it are prose
            i = end if nl < 0 else nl
            continue
        elif ch == "/" and text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = end if close < 0 else close + 2
            continue
        elif ch in "\"'`":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    return text[open_idx + 1 : end]


def _js_params(handler: str, known: list[str]) -> list[str]:
    names = set(known)
    for m in _JS_PARAMS.finditer(handler[:6000], timeout=TIMEOUT):
        g = m.group(1)
        if g.startswith("{"):
            for part in g.strip("{} \n").split(","):
                n = part.split(":")[0].split("=")[0].strip().lstrip(".")
                if regex.match(r"^[A-Za-z_$][\w$]*$", n):
                    names.add(n)
        elif g not in ("extra", "ctx", "context", "req", "res"):
            names.add(g)
    # one level of propagation: const x = <expr using a tainted name>
    for _ in range(2):
        for m in regex.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,300})", handler, timeout=TIMEOUT):
            if any(regex.search(rf"(?<![\w$.]){regex.escape(n)}(?![\w$])", m.group(2), timeout=TIMEOUT) for n in names):
                names.add(m.group(1))
    return sorted(names)


@dataclass
class _Hit:
    kind: str
    offset: int
    sink: str
    source: str
    direct: bool


# Containment / allowlist evidence in the handler (mirrors pytaint.SANITIZERS):
# path and url hits are not reported when it is present.
_JS_SANITIZERS = {
    "path": regex.compile(r"\b(?:validate\w*Path|isPath\w*(?:Within|Allowed)\w*|is(?:Within|Inside|Contained)\w*|"
                          r"assert\w*(?:Within|Allowed|Contained)\w*|ensure\w*(?:Within|Allowed|Contained)\w*)\s*\(|"
                          r"\bpath\.relative\s*\([^)]*\)[^;\n]*startsWith\s*\(\s*['\"]\.\."),
    "url": regex.compile(r"\b(?:ALLOWED_HOSTS|allowedHosts|ALLOWLIST|allowlist|isAllowed(?:Url|Host)\w*)\b"),
}


def js_taint(handler: str, params: list[str]) -> list[_Hit]:
    names = _js_params(handler, params)
    if not names:
        return []
    hits: list[_Hit] = []
    contained = {k for k, rx in _JS_SANITIZERS.items() if rx.search(handler, timeout=TIMEOUT)}
    for rx, kind in _JS_SINKS:
        if kind in contained:
            continue
        for m in rx.finditer(handler, timeout=TIMEOUT):
            args = _call_args(handler, m.end() - 1)
            if kind == "argv" and regex.search(r"\bshell\s*:\s*true\b", args, timeout=TIMEOUT):
                kind_eff = "shell"
            else:
                kind_eff = kind
            first = args.split(",", 1)[0] if kind_eff in ("url", "path", "sql", "template") else args
            for n in names:
                pat = rf"(?<![\w$.'\"]){regex.escape(n)}(?![\w$])"
                if kind_eff == "url":
                    ok = bool(regex.match(rf"\s*(?:{regex.escape(n)}\b|`\$\{{\s*{regex.escape(n)}\b)", first, timeout=TIMEOUT))
                elif kind_eff == "sql":
                    ok = bool(regex.search(rf"\$\{{[^}}]*\b{regex.escape(n)}\b|['\"]\s*\+\s*{regex.escape(n)}\b", first, timeout=TIMEOUT))
                else:
                    ok = bool(regex.search(pat, first, timeout=TIMEOUT))
                if ok:
                    hits.append(_Hit(kind_eff, m.start(), m.group(0).rstrip("( "), n, direct=True))
                    break
    return hits


# ---- capability-evidence patterns --------------------------------------------
_OBFUSCATED = regex.compile(
    r"\b(?:eval|exec)\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|__import__\(\s*['\"]base64|compile\()"
    r"|\beval\s*\(\s*(?:atob|Buffer\.from\([^)]*['\"](?:base64|hex)['\"]\)|String\.fromCharCode|unescape|decodeURIComponent)"
    r"|\bnew\s+Function\s*\(\s*(?:atob|Buffer\.from)|\bFunction\s*\(\s*atob"
    r"|(?:\\x[0-9a-fA-F]{2}){40,}",
)
_RUNNER = (r"\b(?:system|popen|run|call|check_call|check_output|Popen|getoutput|execSync|exec|execa|execaSync|spawnSync|spawn)"
           r"\s*\(\s*(?:shlex\.split\(\s*)?")
_INSTALL = (r"[ \t]*(?:pip3?|uv[ \t]+pip|npm|pnpm|yarn)[ \t]+(?:install|i|add)\b"
            r"(?:[ \t]+(?!-r\b|-e\b|--requirement\b|--editable\b)-[-\w=]+)*[ \t]+"
            r"(?!-r\b|-e\b|--requirement\b|--editable\b|\.)[^\s\"'`-][^\"'`\n]*[\"'`]")
_INSTALL_VAR = regex.compile(r"\b([A-Za-z_]\w*)\s*=\s*f?[\"'`]" + _INSTALL)
_REMOTE_CODE = regex.compile(
    r"\b(?:exec|eval)\s*\(\s*(?:requests\.get|urlopen|urllib\.request\.urlopen|httpx\.get)\s*\("
    r"|\beval\s*\(\s*await\s*\(?\s*(?:await\s+)?(?:fetch|axios)"
    r"|\bimport\s*\(\s*[`'\"]https?://|\brequire\s*\(\s*[`'\"]https?://"
    # An install command naming a package, handed straight to a process runner (a
    # string held in a variable counts only if that variable reaches a runner: see
    # _INSTALL_VAR). One line only, so a closing quote (echo "...") never pairs with
    # the next line; an error message saying "install with `pip install x`" is not
    # a runner; bare `npm install` / `pip install -r req.txt` installs the declared,
    # locked dependencies.
    r"|" + _RUNNER + r"f?[\"'`]" + _INSTALL
    + r"|\[\s*[\"'](?:pip3?|npm|pnpm|yarn)[\"']\s*,\s*[\"'](?:install|i|add)[\"']\s*,(?!\s*[\"'](?:-r|-e|--requirement|\.)[\"'])"
    r"|\b(?:npx|uvx)\s+-y\s",
)
_ANTI_ANALYSIS = regex.compile(
    r"(?:os\.environ\.get\(|os\.getenv\(|process\.env\.|process\.env\[)['\"]?(?:CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|BUILDKITE|TRAVIS)\b"
    r"|/\.dockerenv|\bVBOX|\bvmware\b|\bsys\.gettrace\(\)|\bdebugger;|\bIsDebuggerPresent\b"
    r"|\btime\.sleep\(\s*\d{3,}\s*\)|\bsetTimeout\([^,]{1,200},\s*\d{6,}\s*\)",
    regex.IGNORECASE,
)
_BINARY_DOWNLOAD = regex.compile(
    r"https?://[^\s\"'`]+\.(?:exe|dll|so|dylib|bin|msi|scr|elf)\b"
    r"|\burlretrieve\([^)]*\.(?:exe|so|dll|dylib|bin)\b",
    regex.IGNORECASE,
)
_PASSTHROUGH = regex.compile(
    r"[\"']?[Aa]uthorization[\"']?\s*:\s*(?:req|request|ctx|extra|context)\.(?:headers|authInfo)\b"
    r"|[\"']Authorization[\"']\s*:\s*request\.headers(?:\.get)?\s*[\[(]\s*[\"']authorization"
    r"|headers\s*=\s*(?:dict\()?\s*request\.headers\b",
)
_URL = regex.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?[^\s\"'`)<>]*")
_BENIGN_HOSTS = regex.compile(
    r"(?:^|\.)(?:localhost|example\.(?:com|org|net|invalid)|[a-z0-9-]+\.invalid|json-schema\.org|w3\.org|schema\.org|"
    r"modelcontextprotocol\.io|github\.com|githubusercontent\.com|npmjs\.(?:com|org)|pypi\.org|python\.org|nodejs\.org|"
    r"mozilla\.org|opensource\.org|apache\.org|spdx\.org|docs\.[a-z0-9.-]+)$|^127\.|^0\.0\.0\.0$",
)
_EXFIL_HOSTS = regex.compile(
    r"(?:^|\.)(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|pastebin\.com|transfer\.sh|ngrok(?:-free)?\.(?:io|app|dev)|"
    r"trycloudflare\.com|interact\.sh|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|discord(?:app)?\.com|"
    r"api\.telegram\.org|0x0\.st|file\.io|gofile\.io)$"
)
_DESC_WORDS = {
    CapLabel.code_exec: regex.compile(r"(?i)\b(run|execut|command|shell|script|process|spawn|terminal|eval)"),
    CapLabel.external_egress: regex.compile(r"(?i)\b(fetch|http|api|web|url|remote|download|upload|search|send|post|request|online|internet|sync|github|slack|email|cloud)"),
    CapLabel.destructive: regex.compile(r"(?i)\b(delet|remov|drop|destroy|wipe|purge|overwrite|truncat|clean)"),
    CapLabel.credential_access: regex.compile(r"(?i)\b(credential|secret|token|key|password|auth|login|ssh|aws|keychain)"),
}
_WRITE_EVIDENCE = regex.compile(
    r"\b(?:write_text|write_bytes|writeFile\w*|appendFile\w*|unlink\w*|rmSync|rmdir|shutil\.(?:rmtree|move|copy)|os\.(?:remove|unlink|rename)|"
    r"open\([^)]*,\s*[\"'][wa]|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|requests\.(?:post|put|delete|patch)|"
    r"method\s*:\s*[\"'](?:POST|PUT|DELETE|PATCH)|subprocess|child_process|execSync|exec\()",
)
_DELETE_EVIDENCE = regex.compile(r"\b(?:unlink\w*|rmSync|rm\(|rmdir|shutil\.rmtree|os\.remove|DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE)|TRUNCATE)", regex.IGNORECASE)
_CLIENT_VARIANCE = regex.compile(r"\b(?:clientInfo|client_info|getClientVersion|getClientCapabilities|client_params)\b")
_REMOTE_TOOLS = regex.compile(r"\btools\s*=\s*(?:await\s+)?\(?\s*(?:await\s+)?(?:fetch|requests\.get|httpx\.get|axios\.get)\s*\(")


def _line_of(text: str, offset: int) -> str:
    s = text.rfind("\n", 0, offset) + 1
    e = text.find("\n", offset)
    return text[s : e if e >= 0 else len(text)]


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith(("#", "//", "*", "/*"))


class CodeAnalyzer:
    id: ClassVar[str] = "code"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        "AG-CODE-001", "AG-CODE-002", "AG-CODE-003", "AG-CODE-004", "AG-CODE-005", "AG-CODE-006", "AG-CODE-007",
        "AG-CODE-008", "AG-CODE-020", "AG-CODE-021", "AG-CODE-022", "AG-CODE-023", "AG-CODE-024", "AG-CODE-025",
        "AG-CODE-026", "AG-CODE-027", "AG-CODE-028", "AG-CODE-029", "AG-CODE-040",
        "AG-MCP-META-011", "AG-MCP-META-012", "AG-MCP-META-020",
    )

    def run(self, ctx: Context) -> None:
        inv = ctx.inventory
        handlers: list[ToolHandler] = ctx.data.get("tool_handlers", [])  # type: ignore[assignment]
        handler_caps: dict[tuple[str, str], set[CapLabel]] = {}
        # ---- taint in tool handlers ---------------------------------------
        by_path: dict[str, list[ToolHandler]] = {}
        for h in handlers:
            by_path.setdefault(h.path, []).append(h)
        for path, hs in sorted(by_path.items()):
            at = inv.texts.get(path)
            if at is None:
                continue
            if at.artifact.language == "python":
                self._python(ctx, at, hs, handler_caps)
            elif at.artifact.language in ("javascript", "typescript"):
                self._js(ctx, at, hs, handler_caps)
        # ---- capability evidence ------------------------------------------
        for at in ctx.texts("source_code", "script", "package_manifest"):
            comp = inv.components.get(at.artifact.component_id)
            if comp is None:
                continue
            self._capabilities(ctx, at, comp)
        # ---- declared vs actual per tool ----------------------------------
        self._declared_vs_actual(ctx, handlers, handler_caps)

    # -- Python --------------------------------------------------------------
    def _python(self, ctx: Context, at: ArtifactText, hs: list[ToolHandler], caps: dict) -> None:
        try:
            tree = ast.parse(at.text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return
        aliases = pytaint.import_aliases(tree)
        fns = {f.lineno: f for f in pytaint.tool_functions(tree)}
        for fn in fns.values():
            tool = next((h.tool for h in hs if at.index.line_col(h.start)[0] == fn.lineno), fn.name)
            try:
                hits = pytaint.analyze_function(fn, aliases, at.text)
            except RecursionError:
                continue
            for hit in hits:
                self._emit_taint(ctx, at, tool, hit.kind, Span(path=at.path, start_line=hit.line, start_col=hit.col),
                                 hit.sink, hit.source, Confidence.medium if hit.sanitized else Confidence.high, caps,
                                 [Span(path=at.path, start_line=ln) for ln in hit.path[:5]])
            body = ast.get_source_segment(at.text, fn) or ""
            self._handler_caps(body, (at.artifact.component_id, tool), caps, "python")

    # -- JS / TS -----------------------------------------------------------------
    def _js(self, ctx: Context, at: ArtifactText, hs: list[ToolHandler], caps: dict) -> None:
        for h in hs:
            body = at.text[h.start : h.end]
            for hit in js_taint(body, h.params):
                off = h.start + hit.offset
                sl, sc = at.index.line_col(off)
                self._emit_taint(ctx, at, h.tool, hit.kind, Span(path=at.path, start_line=sl, start_col=sc), hit.sink,
                                 hit.source, Confidence.high if hit.direct else Confidence.medium, caps, [])
            self._handler_caps(body, (at.artifact.component_id, h.tool), caps, at.artifact.language)

    def _emit_taint(self, ctx: Context, at: ArtifactText, tool: str, kind: str, span: Span, sink: str, source: str,
                    conf: Confidence, caps: dict, chain: list[Span]) -> None:
        cid = at.artifact.component_id
        line = at.text.splitlines()[span.start_line - 1] if span.start_line - 1 < len(at.text.splitlines()) else ""
        ctx.emit(TAINT_RULE[kind], component_ids=cid, span=span, snippet=line.strip(), match=f"{tool}:{kind}:{span.start_line}",
                 kind=EvidenceKind.taint, confidence=conf, related=chain,
                 detail=f"tool '{tool}': parameter '{source}' → {sink}",
                 message=f"In tool '{tool}', parameter '{source}' {TAINT_TEXT[kind]} ({sink}).")
        caps.setdefault((cid, tool), set()).add(TAINT_LABEL[kind])
        ctx.add_capability(cid, TAINT_LABEL[kind], subject=f"{cid}#{tool}", confidence=Confidence.high, span=span,
                           snippet=line.strip(), reason=f"tool parameter {TAINT_TEXT[kind]}", kind=EvidenceKind.taint)

    def _handler_caps(self, body: str, key: tuple[str, str], caps: dict, language: str | None) -> None:
        s = caps.setdefault(key, set())
        if search(EGRESS_CODE, body):
            s.add(CapLabel.external_egress)
        if search(regex.compile(r"\bsubprocess\b|child_process|\bexecSync\b|\bspawn\(|\bos\.system\(|\beval\("), body):
            s.add(CapLabel.code_exec)
        if search(_DELETE_EVIDENCE, body):
            s.add(CapLabel.destructive)
        if search(CREDENTIAL_PATH, body) or env_dumps(body, language):
            s.add(CapLabel.credential_access)
        if search(_WRITE_EVIDENCE, body):
            s.add("writes")  # type: ignore[arg-type]  # pseudo-label used only for readOnlyHint checks

    # -- capability evidence -----------------------------------------------------
    def _capabilities(self, ctx: Context, at: ArtifactText, comp: Component) -> None:
        cid = comp.id
        text = at.text
        is_server = comp.kind in (ComponentKind.mcp_server, ComponentKind.package)
        if at.artifact.role == ArtifactRole.package_manifest:
            self._install_hooks(ctx, at, comp)
            return
        # CODE-020/021: server source only (skill scripts use AG-SKL-CRED-*).
        if is_server:
            for m in finditer(CREDENTIAL_PATH, text)[:3]:
                line = _line_of(text, m.start())
                if _is_comment(line):
                    continue
                ctx.emit("AG-CODE-020", component_ids=cid, span=at.span(m.start(), m.end()), snippet=line.strip(),
                         match=m.group(0), kind=EvidenceKind.ast, message=f"Server code references credential store '{m.group(0)[:60]}'.")
                ctx.add_capability(cid, CapLabel.reads_private_data, confidence=Confidence.high, span=at.span(m.start()),
                                   snippet=line.strip(), reason="reads a credential store", kind=EvidenceKind.ast)
                ctx.add_capability(cid, CapLabel.credential_access, confidence=Confidence.high, span=at.span(m.start()),
                                   snippet=line.strip(), reason="reads a credential store", kind=EvidenceKind.ast)
            for m in env_dumps(text, at.artifact.language)[:2]:
                line = _line_of(text, m.start())
                ctx.emit("AG-CODE-021", component_ids=cid, span=at.span(m.start(), m.end()), snippet=line.strip(),
                         match=line.strip(), kind=EvidenceKind.ast, message="Server code serializes or dumps the whole environment.")
            hosts: dict[str, int] = {}
            for m in finditer(_URL, text):
                host = m.group(1).lower().rstrip(".")
                line = _line_of(text, m.start())
                if _is_comment(line) or _BENIGN_HOSTS.search(host) or host in hosts:
                    continue
                hosts[host] = m.start()
            for host, off in list(hosts.items())[:5]:
                exfil = bool(_EXFIL_HOSTS.search(host))
                ctx.emit("AG-CODE-022", component_ids=cid, span=at.span(off), snippet=_line_of(text, off).strip(), match=host,
                         kind=EvidenceKind.ast, severity=Severity.high if exfil else None,
                         message=f"Hardcoded outbound host '{host}'" + (" (known exfiltration sink)." if exfil else "."))
        for rid, pattern, msg in (
            ("AG-CODE-023", _OBFUSCATED, "Code executes decoded or obfuscated content."),
            ("AG-CODE-025", _REMOTE_CODE, "Code fetches or installs code at run time."),
            ("AG-CODE-027", _ANTI_ANALYSIS, "Code checks for CI/sandbox/debugger or delays execution (anti-analysis)."),
            ("AG-CODE-028", _BINARY_DOWNLOAD, "Code downloads or references a native binary."),
            ("AG-CODE-029", _PASSTHROUGH, "Server forwards the client's Authorization header upstream (token passthrough)."),
        ):
            if rid == "AG-CODE-029" and not is_server:
                continue
            hits = finditer(pattern, text)
            if rid == "AG-CODE-025":
                hits += [v for v in finditer(_INSTALL_VAR, text)
                         if search(regex.compile(_RUNNER + regex.escape(v.group(1)) + r"\b"), text)]
            for m in hits[:2]:
                line = _line_of(text, m.start())
                if _is_comment(line) and rid != "AG-CODE-023":
                    continue
                ctx.emit(rid, component_ids=cid, span=at.span(m.start(), m.end()), snippet=line.strip(), match=m.group(0)[:200],
                         kind=EvidenceKind.ast, message=msg)
                if rid in ("AG-CODE-023", "AG-CODE-025"):
                    ctx.add_capability(cid, CapLabel.code_exec, confidence=Confidence.high, span=at.span(m.start()),
                                       snippet=line.strip(), reason="dynamic code execution", kind=EvidenceKind.ast)
                break
        for m in finditer(PERSISTENCE, text)[:2]:
            line = _line_of(text, m.start())
            if _is_comment(line) or not regex.search(r"(?i)\b(open|write|append|>>|tee|copy|cp|mv|crontab|launchctl|schtasks|reg\s+add|systemctl|echo)\b|writeFile|appendFile", line, timeout=TIMEOUT):
                continue
            ctx.emit("AG-CODE-026", component_ids=cid, span=at.span(m.start(), m.end()), snippet=line.strip(), match=m.group(0),
                     kind=EvidenceKind.ast, message=f"Code writes a persistence location ({m.group(0)[:60]}).")
            ctx.add_capability(cid, CapLabel.persistence, confidence=Confidence.high, span=at.span(m.start()),
                               snippet=line.strip(), reason="writes a persistence location", kind=EvidenceKind.ast)
            break
        # Server-level labels from code (for flows).
        if is_server:
            m = search(EGRESS_CODE, text)
            if m:
                ctx.add_capability(cid, CapLabel.external_egress, confidence=Confidence.high, span=at.span(m.start()),
                                   snippet=_line_of(text, m.start()).strip(), reason="network request in server code", kind=EvidenceKind.ast)
            m = search(regex.compile(r"\bsubprocess\.|child_process|\bexecSync\(|\bos\.system\("), text)
            if m:
                ctx.add_capability(cid, CapLabel.code_exec, confidence=Confidence.medium, span=at.span(m.start()),
                                   snippet=_line_of(text, m.start()).strip(), reason="process execution in server code", kind=EvidenceKind.ast)
            m = search(_CLIENT_VARIANCE, text)
            if m and regex.search(r"\b(?:tool|tools|ListTools|list_tools|registerTool)\b", text[max(0, m.start() - 600): m.end() + 600], timeout=TIMEOUT):
                ctx.emit("AG-MCP-META-020", component_ids=cid, span=at.span(m.start()), snippet=_line_of(text, m.start()).strip(),
                         match="client-variance", kind=EvidenceKind.ast,
                         message="Tool definitions appear to depend on the connecting client's identity.")
            m = search(_REMOTE_TOOLS, text)
            if m:
                ctx.emit("AG-MCP-META-020", component_ids=cid, span=at.span(m.start()), snippet=_line_of(text, m.start()).strip(),
                         match="remote-tools", kind=EvidenceKind.ast, message="Tool definitions are fetched from the network at run time.")

    def _install_hooks(self, ctx: Context, at: ArtifactText, comp: Component) -> None:
        name = at.path.rsplit("/", 1)[-1]
        risky = regex.compile(r"\b(?:curl|wget|node\s+-e|python3?\s+-c|bash\s+-c|sh\s+-c|powershell|iwr|https?://)", regex.IGNORECASE)
        if name == "package.json":
            try:
                pkg = json.loads(at.text)
            except (json.JSONDecodeError, RecursionError):
                return
            scripts = pkg.get("scripts") if isinstance(pkg, dict) else None
            if not isinstance(scripts, dict):
                return
            for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
                cmd = scripts.get(hook)
                if isinstance(cmd, str) and cmd.strip():
                    line = at.text.find(f'"{hook}"')
                    danger = bool(search(risky, cmd))
                    ctx.emit("AG-CODE-024", component_ids=comp.id, span=at.span(max(line, 0)), snippet=f'"{hook}": "{cmd}"',
                             match=f"{hook}:{cmd}", kind=EvidenceKind.config, severity=Severity.high if danger else None,
                             message=f"npm lifecycle script '{hook}' runs at install time: {cmd[:80]}")
        elif name == "setup.py":
            m = search(regex.compile(r"\bcmdclass\s*=|^\s*(?:os\.system|subprocess\.\w+|urllib\.request\.urlopen)\(", regex.MULTILINE), at.text)
            if m:
                line = _line_of(at.text, m.start())
                ctx.emit("AG-CODE-024", component_ids=comp.id, span=at.span(m.start()), snippet=line.strip(), match=line.strip(),
                         kind=EvidenceKind.ast, severity=Severity.high if search(risky, at.text) else None,
                         message="setup.py runs custom code at install/build time.")

    # -- declared vs actual --------------------------------------------------------
    def _declared_vs_actual(self, ctx: Context, handlers: list[ToolHandler], caps: dict) -> None:
        tools: dict[tuple[str, str], ToolDef] = {}
        for comp in ctx.inventory.components.values():
            for t in comp.tools:
                tools[(comp.id, t.name)] = t
        for (cid, name), labels in sorted(caps.items()):
            tool = tools.get((cid, name))
            if tool is None:
                continue
            desc = f"{tool.name} {tool.title or ''} {tool.description or ''}"
            ann = tool.annotations or {}
            span = tool.span
            writes = "writes" in labels or CapLabel.code_exec in labels or CapLabel.destructive in labels
            if ann.get("readOnlyHint") is True and writes:
                ctx.emit("AG-MCP-META-011", component_ids=cid, span=span, snippet=f"{name}: readOnlyHint=true", match=f"{name}:ro",
                         kind=EvidenceKind.ast, message=f"Tool '{name}' is annotated readOnlyHint=true but its handler writes, deletes or executes.")
            if ann.get("destructiveHint") is False and CapLabel.destructive in labels:
                ctx.emit("AG-MCP-META-012", component_ids=cid, span=span, snippet=f"{name}: destructiveHint=false", match=f"{name}:destr",
                         kind=EvidenceKind.ast, message=f"Tool '{name}' is annotated destructiveHint=false but its handler deletes data.")
            if ann.get("openWorldHint") is False and CapLabel.external_egress in labels:
                ctx.emit("AG-MCP-META-012", component_ids=cid, span=span, snippet=f"{name}: openWorldHint=false", match=f"{name}:ow",
                         kind=EvidenceKind.ast, message=f"Tool '{name}' is annotated openWorldHint=false but its handler makes network requests.")
            undeclared = [lbl for lbl in (CapLabel.code_exec, CapLabel.external_egress, CapLabel.credential_access)
                          if lbl in labels and not search(_DESC_WORDS[lbl], desc)]
            if undeclared:
                ctx.emit("AG-CODE-040", component_ids=cid, span=span, snippet=(tool.description or name)[:200],
                         match=f"{name}:{','.join(sorted(undeclared))}", kind=EvidenceKind.ast,
                         message=f"Tool '{name}' does not mention it, but its handler shows: {', '.join(l.value for l in undeclared)}.")


def _unused(_: urllib.parse.ParseResult) -> None:
    return None
