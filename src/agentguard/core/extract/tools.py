"""Static extraction of MCP tool registrations from server source code.

Python uses the stdlib ``ast`` module (parse only; nothing is executed or
imported). JavaScript/TypeScript uses conservative regexes over common SDK
call shapes; the optional tree-sitter analyzer refines this when installed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

import regex

from ..models import Span, ToolDef
from ..textutil import TIMEOUT, LineIndex

MAX_SOURCE_FOR_AST = 1_000_000


@dataclass
class ExtractedTool:
    tool: ToolDef
    handler_start: int  # char offset of the handler body (best effort)
    handler_end: int
    params: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- Python ----
def _decorator_is_tool(dec: ast.expr) -> tuple[bool, dict[str, str]]:
    target = dec.func if isinstance(dec, ast.Call) else dec
    name = ""
    if isinstance(target, ast.Attribute):
        name = target.attr
    elif isinstance(target, ast.Name):
        name = target.id
    if name not in ("tool", "mcp_tool"):
        return False, {}
    kwargs: dict[str, str] = {}
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg in ("name", "description", "title") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                kwargs[kw.arg] = kw.value.value
        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
            kwargs.setdefault("name", dec.args[0].value)
        for kw in dec.keywords:
            if kw.arg == "annotations" and isinstance(kw.value, (ast.Dict, ast.Call)):
                kwargs["annotations"] = ast.unparse(kw.value)[:500]
    return True, kwargs


def _py_annotations(src: str) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        m = regex.search(rf"[\"']?{key}[\"']?\s*[:=]\s*(True|False|true|false)", src, timeout=TIMEOUT)
        if m:
            out[key] = m.group(1).lower() == "true"
    return out


def extract_python(path: str, text: str) -> list[ExtractedTool]:
    if len(text) > MAX_SOURCE_FOR_AST:
        return []
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    idx = LineIndex(text)
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)

    def off(lineno: int, col: int) -> int:
        return starts[min(lineno - 1, len(starts) - 1)] + col

    out: list[ExtractedTool] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            ok, kw = _decorator_is_tool(dec)
            if not ok:
                continue
            doc = ast.get_docstring(node) or ""
            params = [a.arg for a in node.args.args + node.args.kwonlyargs if a.arg not in ("self", "ctx", "context")]
            props: dict[str, dict] = {}
            for a in node.args.args + node.args.kwonlyargs:
                if a.arg in ("self", "ctx", "context"):
                    continue
                typ = "string"
                if a.annotation is not None:
                    ann = ast.unparse(a.annotation)
                    typ = {"int": "integer", "float": "number", "bool": "boolean", "dict": "object", "list": "array"}.get(ann.split("[")[0], "string")
                props[a.arg] = {"type": typ}
            end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
            tool = ToolDef(
                name=kw.get("name", node.name),
                title=kw.get("title"),
                description=kw.get("description", doc) or None,
                input_schema={"type": "object", "properties": props},
                annotations=_py_annotations(kw.get("annotations", "")),
                origin="source_extraction",
                span=Span(path=path, start_line=node.lineno),
            )
            out.append(ExtractedTool(tool, off(node.lineno, 0), off(end_line, 0) if end_line < len(starts) else len(text), params))
            break
    _ = idx
    return out


# ------------------------------------------------------------ JS / TS -------
_STR = r"""(?:"((?:[^"\\\n]|\\.){0,4000})"|'((?:[^'\\\n]|\\.){0,4000})'|`((?:[^`\\]|\\.){0,8000})`)"""
_TOOL_CALL = regex.compile(r"\.\s*(?:tool|registerTool|addTool)\s*\(\s*" + _STR + r"\s*,\s*(?:" + _STR + r")?", regex.DOTALL)
_OBJ_TOOL = regex.compile(r"\bname\s*:\s*" + _STR + r"\s*,\s*(?:title\s*:\s*" + _STR + r"\s*,\s*)?description\s*:\s*" + _STR, regex.DOTALL)
_DESC_IN_CONFIG = regex.compile(r"\bdescription\s*:\s*" + _STR, regex.DOTALL)
_PARAM = regex.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*z\.(string|number|boolean|object|array|enum|any)\(\)?(?:[^,\n]*?\.describe\(\s*" + _STR + r"\s*\))?")
_ANNOT = regex.compile(r"\b(readOnlyHint|destructiveHint|idempotentHint|openWorldHint)\s*:\s*(true|false)")


_JS_ESC = regex.compile(r"\\(u\{[0-9A-Fa-f]{1,6}\}|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|.)", regex.DOTALL)
_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def js_unescape(s: str) -> str:
    """Decode JS string escapes without touching literal non-ASCII characters."""
    if "\\" not in s:
        return s

    def rep(m: regex.Match[str]) -> str:
        e = m.group(1)
        if e.startswith("u{"):
            cp = int(e[2:-1], 16)
            return chr(cp) if cp <= 0x10FFFF else ""
        if e.startswith("u") and len(e) == 5:
            return chr(int(e[1:], 16))
        if e.startswith("x") and len(e) == 3:
            return chr(int(e[1:], 16))
        return _SIMPLE.get(e, e)

    return _JS_ESC.sub(rep, s)


def _first(m: regex.Match[str], groups: tuple[int, ...]) -> str | None:
    for g in groups:
        v = m.group(g)
        if v is not None:
            return js_unescape(v)
    return None


def _handler_end(text: str, start: int, limit: int = 20_000) -> int:
    """Find the end of the call starting at ``start`` by bracket matching."""
    depth = 0
    i = text.find("(", start)
    if i < 0:
        return min(len(text), start + 2000)
    end = min(len(text), i + limit)
    in_str: str | None = None
    while i < end:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'`":
            in_str = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return end


def extract_js(path: str, text: str) -> list[ExtractedTool]:
    idx = LineIndex(text)
    out: list[ExtractedTool] = []
    seen: set[str] = set()
    try:
        calls = list(_TOOL_CALL.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        calls = []
    for m in calls:
        name = _first(m, (1, 2, 3))
        if not name or name in seen or not regex.match(r"^[A-Za-z0-9_.\-]{1,128}$", name):
            continue
        seen.add(name)
        end = _handler_end(text, m.start())
        body = text[m.start() : end]
        desc = _first(m, (4, 5, 6))
        if desc is None:
            dm = _DESC_IN_CONFIG.search(body[:4000], timeout=TIMEOUT)
            desc = _first(dm, (1, 2, 3)) if dm else None
        props: dict[str, dict] = {}
        for pm in _PARAM.finditer(body[:8000], timeout=TIMEOUT):
            pdesc = _first(pm, (3, 4, 5))
            props[pm.group(1)] = {"type": pm.group(2) if pm.group(2) != "enum" else "string", **({"description": pdesc} if pdesc else {})}
        annotations = {k: v == "true" for k, v in _ANNOT.findall(body[:8000])}
        out.append(
            ExtractedTool(
                ToolDef(name=name, description=desc, input_schema={"type": "object", "properties": props},
                        annotations=annotations, origin="source_extraction",
                        span=Span(path=path, start_line=idx.line_col(m.start())[0])),
                m.start(), end, list(props),
            )
        )
    if not out:
        try:
            objs = list(_OBJ_TOOL.finditer(text, timeout=TIMEOUT))
        except TimeoutError:
            objs = []
        for m in objs:
            name = _first(m, (1, 2, 3))
            if not name or name in seen or not regex.match(r"^[A-Za-z0-9_.\-]{1,128}$", name):
                continue
            window = text[m.start() : m.start() + 3000]
            if "inputSchema" not in window and "input_schema" not in window:
                continue
            seen.add(name)
            out.append(
                ExtractedTool(
                    ToolDef(name=name, title=_first(m, (4, 5, 6)), description=_first(m, (7, 8, 9)),
                            origin="source_extraction", span=Span(path=path, start_line=idx.line_col(m.start())[0])),
                    m.start(), min(len(text), m.start() + 3000), [],
                )
            )
    return out


def extract_tools(path: str, text: str, language: str | None) -> list[ExtractedTool]:
    if language == "python":
        return extract_python(path, text)
    if language in ("javascript", "typescript"):
        return extract_js(path, text)
    return []
