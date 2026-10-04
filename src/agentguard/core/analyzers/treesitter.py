"""Optional tree-sitter code analyzer (``code.ts``; install ``agentguard[code]``).

Syntax-aware, intra-procedural taint on top of the pattern-based code analyzer:

* JavaScript/TypeScript MCP tool handlers. The handler's first parameter
  (including nested destructured fields) is tracked through declarations,
  assignments, destructuring, ``for … of``, member access, templates,
  concatenation and calls into the sinks of AG-CODE-001..008. A handler passed
  by name (``server.tool("x", schema, handler)``) is resolved within the file,
  and sinks are resolved through imports and ``promisify`` aliases of
  ``child_process``, ``fs`` and ``execa``.
* Shell scripts (bundled skill scripts, shell servers). Positional arguments
  (``$1``, ``$@``, …) and ``read`` variables are tracked into ``eval``,
  ``sh -c`` and ``source``.

The analyzer only adds findings: a hit on the same line as the pattern
analyzer's merges with it (same rule, tool and line). Python keeps the stdlib
``ast`` taint in pytaint, which is already a full parse.

The grammars are native extensions, so this analyzer is skipped (and reported
as skipped) where they are not installed, including the browser build.
Parsing is bounded by input size and node budgets; nothing is executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Iterator

import regex

from ..artifacts import ArtifactText
from ..models import Span
from ..models.enums import Confidence
from ..textutil import TIMEOUT
from .base import Context
from .code import _JS_SANITIZERS, emit_taint
from .mcp import ToolHandler

MAX_SOURCE_BYTES = 1_000_000
MAX_NODES = 200_000          # per walk
MAX_EXPR_DEPTH = 64          # deeper expressions are treated as untainted (conservative)

_GRAMMARS: dict[str, Any] = {}


def _parser(grammar: str) -> Any:
    import tree_sitter as ts  # native; only reached when installed

    lang = _GRAMMARS.get(grammar)
    if lang is None:
        if grammar == "javascript":
            import tree_sitter_javascript as g

            lang = ts.Language(g.language())
        elif grammar in ("typescript", "tsx"):
            import tree_sitter_typescript as g

            lang = ts.Language(g.language_tsx() if grammar == "tsx" else g.language_typescript())
        else:
            import tree_sitter_bash as g

            lang = ts.Language(g.language())
        _GRAMMARS[grammar] = lang
    return ts.Parser(lang)


def _grammar(at: ArtifactText) -> str | None:
    lang = at.artifact.language
    if lang == "javascript":
        return "javascript"
    if lang == "typescript":
        return "tsx" if at.path.lower().endswith(".tsx") else "typescript"
    if lang == "shell":
        return "bash"
    return None


class _Src:
    """Byte/char offset conversion: tree-sitter works on UTF-8 bytes, spans on str offsets."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.data = text.encode("utf-8", "surrogatepass")
        self.ascii = len(self.data) == len(text)

    def to_byte(self, c: int) -> int:
        return c if self.ascii else len(self.text[:c].encode("utf-8", "surrogatepass"))

    def to_char(self, b: int) -> int:
        return b if self.ascii else len(self.data[:b].decode("utf-8", "surrogatepass"))

    def of(self, node: Any) -> str:
        return self.data[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _walk(node: Any, limit: int = MAX_NODES) -> Iterator[Any]:
    stack = [node]
    seen = 0
    while stack and seen < limit:
        cur = stack.pop()
        seen += 1
        yield cur
        stack.extend(reversed(cur.children))


def _named(node: Any) -> list[Any]:
    return [c for c in node.named_children if c.type != "comment"] if node is not None else []


@dataclass
class _Hit:
    kind: str
    node: Any
    sink: str
    source: str


# ---- JavaScript / TypeScript ---------------------------------------------------
RAW, PREFIX, BUILT = "raw", "prefix", "built"   # fully controlled · controls the start · contains input
_RANK = {None: 0, BUILT: 1, PREFIX: 2, RAW: 3}

_FUNCTIONS = {"arrow_function", "function_expression", "function", "generator_function", "function_declaration",
              "generator_function_declaration"}
_PASS_FIRST = {"parenthesized_expression", "await_expression", "as_expression", "satisfies_expression",
               "non_null_expression", "spread_element"}
_NOT_INPUT = {"extra", "_extra", "ctx", "context", "req", "res", "_"}
_STRING_METHODS = {"trim", "trimStart", "trimEnd", "toString", "toLowerCase", "toUpperCase", "normalize", "valueOf",
                   "toLocaleLowerCase", "toLocaleUpperCase"}
_UNTAINT = regex.compile(
    r"^(?:Number|parseInt|parseFloat|Boolean|isNaN|Math\.\w+|path\.basename|"
    r"(?:\w+\.)*\w*(?:[Vv]alidate|[Ss]anitize|[Ee]scape|[Qq]uote|[Aa]ssert|isAllowed|isSafe)\w*)$"
)

_CP = {"exec": "shell", "execSync": "shell", "spawn": "argv", "spawnSync": "argv", "execFile": "argv",
       "execFileSync": "argv", "fork": "argv"}
_EXECA = {"execa": "argv", "execaSync": "argv", "execaCommand": "shell", "execaCommandSync": "shell"}
_FS = {"readFile", "writeFile", "appendFile", "unlink", "rm", "rmdir", "readdir", "createReadStream", "createWriteStream",
       "readFileSync", "writeFileSync", "appendFileSync", "unlinkSync", "rmSync", "rmdirSync", "readdirSync", "copyFile",
       "copyFileSync", "rename", "renameSync", "open", "openSync", "cp", "cpSync", "mkdir", "mkdirSync"}
_FS_MODULES = {"fs", "fs/promises", "fs-extra", "graceful-fs"}
_HTTP_LIBS = {"axios", "got", "ky", "undici", "node-fetch", "superagent"}
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "stream"}
_SQL_METHODS = {"query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "exec"}
_TEMPLATE_LIBS = {"ejs", "Handlebars", "handlebars", "pug", "nunjucks", "_", "lodash"}
_TEMPLATE_METHODS = {"render", "compile", "renderString", "template", "renderFile"}


@dataclass
class _Imports:
    """What the file binds to dangerous modules (by local name)."""

    funcs: dict[str, str]        # local name → sink kind (exec, spawn, execa, readFile …)
    namespaces: dict[str, str]   # local name → "child_process" | "fs"


def _module(spec: str) -> str:
    spec = spec.strip("'\"`")
    return spec[5:] if spec.startswith("node:") else spec


def _bind_module(imp: _Imports, module: str, local: str, imported: str | None) -> None:
    """``imported`` is the exported name, or None for a default/namespace binding."""
    if module == "child_process":
        if imported is None:
            imp.namespaces[local] = "child_process"
        elif imported in _CP:
            imp.funcs[local] = _CP[imported]
    elif module in _FS_MODULES:
        if imported is None or imported == "promises":
            imp.namespaces[local] = "fs"
        elif imported in _FS:
            imp.funcs[local] = "path"
    elif module == "execa":
        if imported in _EXECA:
            imp.funcs[local] = _EXECA[imported]
        elif imported is None:
            imp.funcs[local] = "argv"


def _imports(root: Any, src: _Src) -> _Imports:
    imp = _Imports({}, {})
    promisified: list[tuple[str, Any]] = []
    for n in _walk(root):
        if n.type == "import_statement":
            source = n.child_by_field_name("source")
            if source is None:
                continue
            module = _module(src.of(source))
            for c in _walk(n, 200):
                if c.type == "import_specifier":
                    name = c.child_by_field_name("name")
                    alias = c.child_by_field_name("alias")
                    if name is not None:
                        _bind_module(imp, module, src.of(alias or name), src.of(name))
                elif c.type == "namespace_import":
                    ident = next((x for x in c.named_children if x.type == "identifier"), None)
                    if ident is not None:
                        _bind_module(imp, module, src.of(ident), None)
                elif c.type == "import_clause":
                    default = next((x for x in c.named_children if x.type == "identifier"), None)
                    if default is not None:
                        _bind_module(imp, module, src.of(default), None)
        elif n.type == "variable_declarator":
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is None or value is None:
                continue
            while value.type in ("await_expression", "parenthesized_expression") and _named(value):
                value = _named(value)[0]
            if value.type != "call_expression":
                continue
            fn = src.of(value.child_by_field_name("function") or value).replace(" ", "")
            args = _named(value.child_by_field_name("arguments"))
            if fn in ("require", "import") and args and args[0].type == "string":
                module = _module(src.of(args[0]))
                if name.type == "identifier":
                    _bind_module(imp, module, src.of(name), None)
                elif name.type == "object_pattern":
                    for p in _named(name):
                        if p.type == "shorthand_property_identifier_pattern":
                            _bind_module(imp, module, src.of(p), src.of(p))
                        elif p.type == "pair_pattern":
                            key, val = p.child_by_field_name("key"), p.child_by_field_name("value")
                            if key is not None and val is not None and val.type == "identifier":
                                _bind_module(imp, module, src.of(val), src.of(key))
            elif fn in ("promisify", "util.promisify") and args and name.type == "identifier":
                promisified.append((src.of(name), args[0]))
    for local, target in promisified:   # const run = promisify(exec) / promisify(cp.exec)
        kind = _sink_kind(target, src, imp, as_callee=True)
        if kind:
            imp.funcs[local] = kind
    return imp


def _sink_kind(callee: Any, src: _Src, imp: _Imports, *, as_callee: bool = False) -> str | None:
    """Sink kind of a callee expression (identifier or member expression)."""
    if callee is None:
        return None
    if callee.type == "identifier":
        name = src.of(callee)
        if name == "eval":
            return "eval"
        if name in imp.funcs:
            return imp.funcs[name]
        if name == "fetch" or name in ("axios", "got", "ky"):
            return "url"
        if name in ("unserialize", "deserialize"):
            return "deser"
        return None
    if callee.type != "member_expression":
        return None
    obj, prop = callee.child_by_field_name("object"), callee.child_by_field_name("property")
    if obj is None or prop is None:
        return None
    o, p = src.of(obj).replace("?.", ".").replace(" ", ""), src.of(prop)
    base = o.split(".", 1)[0]
    if imp.namespaces.get(base) == "child_process" and o == base and p in _CP:
        return _CP[p]
    if imp.namespaces.get(base) == "fs" and o in (base, f"{base}.promises") and p in _FS:
        return "path"
    if (o in _HTTP_LIBS or o in ("http", "https")) and p in _HTTP_METHODS:
        return "url"
    if o == "vm" and p.startswith("run"):
        return "eval"
    if p in _TEMPLATE_METHODS and o in _TEMPLATE_LIBS:
        return "template"
    if p in ("unserialize", "deserialize"):
        return "deser"
    if p in _SQL_METHODS and not as_callee and not (p == "exec" and obj.type == "regex"):   # /re/.exec(s) is not SQL
        return "sql"
    return None


class _JsFunction:
    """Taint state for one handler function."""

    def __init__(self, fn: Any, src: _Src, imp: _Imports) -> None:
        self.fn, self.src, self.imp = fn, src, imp
        self.env: dict[str, str] = {}
        self.origin: dict[str, str] = {}   # tainted name → the parameter it came from

    # -- sources -------------------------------------------------------------------
    def bind_params(self) -> bool:
        single = self.fn.child_by_field_name("parameter")
        params = _named(self.fn.child_by_field_name("parameters"))
        first = single if single is not None else (params[0] if params else None)
        if first is None:
            return False
        if first.type in ("required_parameter", "optional_parameter"):
            first = first.child_by_field_name("pattern") or first
        if first.type == "assignment_pattern":
            first = first.child_by_field_name("left") or first
        if first.type == "identifier" and self.src.of(first) in _NOT_INPUT:
            return False
        for name in self._pattern_names(first):
            self.env[name] = RAW
            self.origin[name] = name
        return bool(self.env)

    def _pattern_names(self, pat: Any) -> list[str]:
        out: list[str] = []
        stack = [pat]
        while stack:
            n = stack.pop()
            if n.type in ("identifier", "shorthand_property_identifier_pattern"):
                out.append(self.src.of(n))
            elif n.type == "pair_pattern":
                v = n.child_by_field_name("value")
                if v is not None:
                    stack.append(v)
            elif n.type in ("assignment_pattern", "object_assignment_pattern"):
                left = n.child_by_field_name("left")
                if left is not None:
                    stack.append(left)
            elif n.type not in ("type_annotation", "comment", "property_identifier", "accessibility_modifier"):
                stack.extend(_named(n))
        return out

    def _bind(self, name: str, flavor: str | None, origin: str) -> bool:
        if flavor and _RANK[flavor] > _RANK[self.env.get(name)]:
            self.env[name] = flavor
            self.origin.setdefault(name, origin)
            return True
        return False

    # -- propagation (flow-insensitive, to a fixpoint) -----------------------------
    def propagate(self, body: Any) -> None:
        defs = [n for n in _walk(body) if n.type in ("variable_declarator", "assignment_expression",
                                                    "augmented_assignment_expression", "for_in_statement")]
        for _ in range(6):
            changed = False
            for n in defs:
                if n.type == "variable_declarator":
                    left, right = n.child_by_field_name("name"), n.child_by_field_name("value")
                elif n.type == "for_in_statement":
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                else:
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is None or right is None:
                    continue
                f = self.flavor(right)
                if not f:
                    continue
                if n.type == "augmented_assignment_expression":
                    f = BUILT
                origin = self.source_name(right)
                if left.type == "identifier":
                    changed |= self._bind(self.src.of(left), f, origin)
                else:
                    for name in self._pattern_names(left):
                        changed |= self._bind(name, RAW if f == RAW else BUILT, origin)
            if not changed:
                break

    # -- expressions -------------------------------------------------------------------
    def flavor(self, n: Any, depth: int = 0) -> str | None:
        if n is None or depth > MAX_EXPR_DEPTH:
            return None
        t = n.type
        if t in ("identifier", "shorthand_property_identifier"):
            return self.env.get(self.src.of(n))
        if t in ("member_expression", "subscript_expression"):
            f = self.flavor(n.child_by_field_name("object"), depth + 1)
            return RAW if f == RAW else (BUILT if f else None)
        if t in _PASS_FIRST:
            kids = _named(n)
            return self.flavor(kids[0] if kids else None, depth + 1)
        if t == "type_assertion":
            kids = _named(n)
            return self.flavor(kids[-1] if kids else None, depth + 1)
        if t == "template_string":
            subs = [c for c in n.children if c.type == "template_substitution"]
            flavors = [self.flavor(_named(c)[0] if _named(c) else None, depth + 1) for c in subs]
            if not any(flavors):
                return None
            parts = [c for c in n.children if c.type not in ("`",)]
            if len(parts) == 1 and flavors[0]:
                return flavors[0]
            if parts and parts[0].type == "template_substitution" and flavors[0] in (RAW, PREFIX):
                return PREFIX
            return BUILT
        if t == "binary_expression":
            op = n.child_by_field_name("operator")
            opt = self.src.of(op) if op is not None else ""
            left = self.flavor(n.child_by_field_name("left"), depth + 1)
            right = self.flavor(n.child_by_field_name("right"), depth + 1)
            if opt == "+":
                return PREFIX if left in (RAW, PREFIX) else (BUILT if left or right else None)
            if opt in ("||", "??"):
                return max(left, right, key=lambda f: _RANK[f])
            if opt == "&&":
                return right
            return None
        if t == "ternary_expression":
            a = self.flavor(n.child_by_field_name("consequence"), depth + 1)
            b = self.flavor(n.child_by_field_name("alternative"), depth + 1)
            return max(a, b, key=lambda f: _RANK[f])
        if t == "assignment_expression":
            return self.flavor(n.child_by_field_name("right"), depth + 1)
        if t == "sequence_expression":
            kids = _named(n)
            return self.flavor(kids[-1] if kids else None, depth + 1)
        if t == "call_expression":
            fn = n.child_by_field_name("function")
            name = self.src.of(fn).replace(" ", "") if fn is not None else ""
            args = _named(n.child_by_field_name("arguments"))
            if _UNTAINT.match(name, timeout=TIMEOUT):
                return None
            if name == "String" and args:
                return self.flavor(args[0], depth + 1)
            if fn is not None and fn.type == "member_expression":
                recv = self.flavor(fn.child_by_field_name("object"), depth + 1)
                if recv:
                    prop = fn.child_by_field_name("property")
                    return RAW if recv == RAW and prop is not None and self.src.of(prop) in _STRING_METHODS else BUILT
            return BUILT if any(self.flavor(a, depth + 1) for a in args) else None
        if t == "new_expression":
            ctor = n.child_by_field_name("constructor")
            args = _named(n.child_by_field_name("arguments"))
            if ctor is not None and self.src.of(ctor) == "URL" and args:
                return self.flavor(args[0], depth + 1)
            return BUILT if any(self.flavor(a, depth + 1) for a in args) else None
        if t in ("array", "object"):
            for c in _named(n):
                target = c.child_by_field_name("value") if c.type == "pair" else c
                if self.flavor(target, depth + 1):
                    return BUILT
            return None
        return None

    def source_name(self, n: Any) -> str:
        """The handler parameter a tainted expression came from."""
        for c in _walk(n, 2000):
            if c.type in ("identifier", "shorthand_property_identifier") and self.src.of(c) in self.env:
                return self.origin.get(self.src.of(c), self.src.of(c))
        return "?"

    # -- sinks --------------------------------------------------------------------------
    def sinks(self, body: Any) -> list[_Hit]:
        hits: list[_Hit] = []
        for n in _walk(body):
            if n.type == "call_expression":
                callee = n.child_by_field_name("function")
                kind = _sink_kind(callee, self.src, self.imp)
            elif n.type == "new_expression":
                callee = n.child_by_field_name("constructor")
                text = self.src.of(callee) if callee is not None else ""
                kind = "eval" if text in ("Function", "vm.Script") else None
            else:
                continue
            if kind is None:
                continue
            args = _named(n.child_by_field_name("arguments"))
            if not args:
                continue
            if kind == "argv" and any(self._shell_option(a) for a in args):
                kind = "shell"
            if kind in ("shell", "argv", "eval", "deser"):
                hit = next((a for a in args if self.flavor(a)), None)
            else:
                f = self.flavor(args[0])
                ok = {"url": f in (RAW, PREFIX), "sql": f in (PREFIX, BUILT), "path": bool(f), "template": bool(f)}[kind]
                hit = args[0] if ok else None
            if hit is not None:
                hits.append(_Hit(kind, n, self.src.of(callee).replace("\n", " ")[:60] if callee is not None else kind,
                                 self.source_name(hit)))
        return hits

    def _shell_option(self, arg: Any) -> bool:
        if arg.type != "object":
            return False
        for pair in _named(arg):
            if pair.type == "pair":
                key, value = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                if key is not None and value is not None and self.src.of(key).strip("'\"") == "shell" and value.type != "false":
                    return True
        return False


def _handler_function(root: Any, src: _Src, h: ToolHandler) -> Any:
    sb, eb = src.to_byte(h.start), src.to_byte(h.end)
    node = root.descendant_for_byte_range(sb, max(sb, eb - 1))
    while node is not None and node.type != "call_expression":
        node = node.parent
    if node is None:
        return None
    args = _named(node.child_by_field_name("arguments"))
    fn = next((a for a in reversed(args) if a.type in _FUNCTIONS), None)
    if fn is not None:
        return fn
    ref = args[-1] if args and args[-1].type == "identifier" else None
    if ref is None:
        return None
    name = src.of(ref)
    for n in _walk(root):   # a handler passed by name: resolve it within the file
        if n.type in ("function_declaration", "generator_function_declaration"):
            ident = n.child_by_field_name("name")
            if ident is not None and src.of(ident) == name:
                return n
        elif n.type == "variable_declarator":
            ident, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if ident is not None and value is not None and src.of(ident) == name and value.type in _FUNCTIONS:
                return value
    return None


# ---- shell ------------------------------------------------------------------------
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
_POSITIONAL = regex.compile(r"^(?:[0-9]+|[@*])$")


class _ShellScript:
    def __init__(self, root: Any, src: _Src) -> None:
        self.root, self.src = root, src
        self.env: dict[str, str] = {}   # tainted variable → the argument it came from ("$1", "read")

    def _expansions(self, n: Any) -> Iterator[str]:
        for c in _walk(n, 5000):
            if c.type in ("simple_expansion", "expansion"):
                name = next((x for x in c.named_children if x.type in ("variable_name", "special_variable_name")), None)
                if name is not None:
                    yield self.src.of(name)

    def tainted(self, n: Any) -> str | None:
        for name in self._expansions(n):
            if _POSITIONAL.match(name):
                return f"${name}"
            if name in self.env:
                return self.env[name]
        return None

    def propagate(self) -> None:
        nodes = [n for n in _walk(self.root) if n.type in ("variable_assignment", "command", "for_statement")]
        for _ in range(6):
            before = len(self.env)
            for n in nodes:
                if n.type == "variable_assignment":
                    name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                    origin = self.tainted(value) if name is not None and value is not None else None
                    if origin:
                        self.env.setdefault(self.src.of(name), origin)
                elif n.type == "for_statement":
                    var = n.child_by_field_name("variable")
                    values = n.children_by_field_name("value")
                    origin = "$@" if not values else next((o for o in (self.tainted(v) for v in values) if o), None)
                    if var is not None and origin:
                        self.env.setdefault(self.src.of(var), origin)   # `for x; do` iterates over "$@"
                elif self._name(n) == "read":
                    for arg in n.children_by_field_name("argument"):
                        word = self.src.of(arg)
                        if regex.match(r"^[A-Za-z_]\w*$", word):
                            self.env.setdefault(word, "read")
            if len(self.env) == before:
                break

    def _name(self, cmd: Any) -> str:
        name = cmd.child_by_field_name("name")
        return self.src.of(name).rsplit("/", 1)[-1] if name is not None else ""

    def sinks(self) -> list[_Hit]:
        hits: list[_Hit] = []
        for n in _walk(self.root):
            if n.type != "command":
                continue
            name = self._name(n)
            args = n.children_by_field_name("argument")
            if name == "eval" or name in ("source", "."):
                src = next((s for s in (self.tainted(a) for a in args) if s), None)
                if src:
                    hits.append(_Hit("eval", n, name, src))
            elif name in _SHELLS:
                words = [self.src.of(a) for a in args]
                if "-c" in words:
                    i = words.index("-c")
                    src = self.tainted(args[i + 1]) if i + 1 < len(args) else None
                    if src:
                        hits.append(_Hit("shell", n, f"{name} -c", src))
        return hits


# ---- analyzer -----------------------------------------------------------------------
class TreeSitterAnalyzer:
    id: ClassVar[str] = "code.ts"
    requires: ClassVar[frozenset[str]] = frozenset({"native"})
    native_modules: ClassVar[tuple[str, ...]] = (
        "tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript", "tree_sitter_bash",
    )
    rules: ClassVar[tuple[str, ...]] = (
        "AG-CODE-001", "AG-CODE-002", "AG-CODE-003", "AG-CODE-004", "AG-CODE-005", "AG-CODE-006", "AG-CODE-007",
        "AG-CODE-008",
    )

    def run(self, ctx: Context) -> None:
        handlers: list[ToolHandler] = ctx.data.get("tool_handlers", [])  # type: ignore[assignment]
        by_path: dict[str, list[ToolHandler]] = {}
        for h in handlers:
            by_path.setdefault(h.path, []).append(h)
        for path, hs in sorted(by_path.items()):
            at = ctx.inventory.texts.get(path)
            grammar = _grammar(at) if at is not None else None
            if at is None or grammar not in ("javascript", "typescript", "tsx"):
                continue
            parsed = self._parse(at, grammar)
            if parsed is None:
                continue
            root, src = parsed
            imp = _imports(root, src)
            for h in sorted(hs, key=lambda h: (h.start, h.tool)):
                self._handler(ctx, at, root, src, imp, h)
        for at in ctx.texts("script", "source_code"):
            if _grammar(at) != "bash":
                continue
            parsed = self._parse(at, "bash")
            if parsed is None:
                continue
            root, src = parsed
            script = _ShellScript(root, src)
            script.propagate()
            comp = ctx.inventory.components.get(at.artifact.component_id)
            rel = at.path[len(comp.root) + 1 :] if comp and comp.root and at.path.startswith(comp.root + "/") else at.path
            for hit in self._dedupe(script.sinks()):
                self._emit(ctx, at, src, rel, hit, script=True)

    def _parse(self, at: ArtifactText, grammar: str) -> tuple[Any, _Src] | None:
        src = _Src(at.text)
        if len(src.data) > MAX_SOURCE_BYTES:
            return None
        return _parser(grammar).parse(src.data).root_node, src

    def _handler(self, ctx: Context, at: ArtifactText, root: Any, src: _Src, imp: _Imports, h: ToolHandler) -> None:
        fn = _handler_function(root, src, h)
        if fn is None:
            return
        state = _JsFunction(fn, src, imp)
        if not state.bind_params():
            return
        body = fn.child_by_field_name("body") or fn
        state.propagate(body)
        body_text = src.of(body)
        contained = {k for k, rx in _JS_SANITIZERS.items() if rx.search(body_text, timeout=TIMEOUT)}
        hits = [hit for hit in state.sinks(body) if hit.kind not in contained]
        for hit in self._dedupe(hits):
            self._emit(ctx, at, src, h.tool, hit, script=False)

    @staticmethod
    def _dedupe(hits: list[_Hit]) -> list[_Hit]:
        seen: set[tuple[str, int]] = set()
        out = []
        for hit in sorted(hits, key=lambda h: (h.node.start_byte, h.kind)):
            key = (hit.kind, hit.node.start_point[0])
            if key not in seen:
                seen.add(key)
                out.append(hit)
        return out

    def _emit(self, ctx: Context, at: ArtifactText, src: _Src, tool: str, hit: _Hit, *, script: bool) -> None:
        start = src.to_char(hit.node.start_byte)
        line, col = at.index.line_col(start)
        emit_taint(ctx, at, tool, hit.kind, Span(path=at.path, start_line=line, start_col=col), hit.sink, hit.source,
                   Confidence.high, {}, [], script=script)
