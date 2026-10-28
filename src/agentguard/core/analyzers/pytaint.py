"""Taint analysis for Python MCP tool handlers (stdlib ``ast``; parse-only,
nothing is imported or executed).

Sources: the handler's parameters. Propagation: assignments (incl. augmented,
annotated, tuple unpacking, for-targets, with-as), f-strings, concatenation,
%-formatting, str.format, str methods, subscripts/attributes of tainted values,
and calls taking tainted arguments (conservative). Sinks are listed in SINKS.

With a ``Resolver``, a tainted argument passed to a helper function of the same
component is followed into it: a function of the same file, one imported from a
module of the component (``from .shell import run``, ``from . import engine``,
sibling and package imports), or a method of the same class through ``self``.
Each helper is summarized per parameter (which sinks that parameter reaches,
after the helper's own sanitizers), at most MAX_DEPTH helpers deep. Installed
packages, dynamic imports and ``getattr`` dispatch are not followed.
"""

from __future__ import annotations

import ast
import posixpath
from dataclasses import dataclass, field

SHELL_TRUE_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
SHELL_FUNCS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput",
               "asyncio.create_subprocess_shell"}
ARGV_FUNCS = SHELL_TRUE_FUNCS | {"os.execv", "os.execvp", "os.execve", "os.execl", "os.execlp", "os.spawnv", "os.spawnvp",
                                 "asyncio.create_subprocess_exec"}
EVAL_FUNCS = {"eval", "exec", "compile", "builtins.eval", "builtins.exec"}
DESER_FUNCS = {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "dill.loads", "jsonpickle.decode",
               "yaml.unsafe_load", "yaml.full_load", "shelve.open", "torch.load", "joblib.load"}
PATH_FUNCS = {"open", "io.open", "os.remove", "os.unlink", "os.rmdir", "os.rename", "os.replace", "os.makedirs", "os.mkdir",
              "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.move", "pathlib.Path", "Path", "os.open",
              "os.listdir", "os.scandir", "os.walk", "glob.glob", "send_file", "FileResponse"}
URL_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.head",
             "requests.request", "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
             "urllib.request.urlopen", "urlopen", "urllib.request.Request", "aiohttp.request"}
URL_METHODS = {"get", "post", "put", "patch", "delete", "request", "head", "stream"}  # on client/session objects
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
TEMPLATE_FUNCS = {"jinja2.Template", "Template", "render_template_string", "mako.template.Template"}
TEMPLATE_METHODS = {"from_string"}
# Kind-specific evidence of sanitization in the handler body (heuristic).
SANITIZERS: dict[str, tuple[str, ...]] = {
    "path": ("is_relative_to", "commonpath", "os.path.commonprefix"),
    "url": ("ALLOWED_HOSTS", "allowed_hosts", "ALLOWLIST", "allowlist", "is_private", "is_global"),
    "shell": ("shlex.quote", "pipes.quote"),
    "argv": ("shlex.quote", "startswith(\"-\")", "startswith('-')", "re.fullmatch", "re.match"),
}


@dataclass
class TaintHit:
    kind: str           # shell | argv | eval | deser | path | url | sql | template
    line: int
    col: int
    sink: str
    source: str         # tainted variable reaching the sink
    sanitized: bool = False
    path: list[int] = field(default_factory=list)  # lines of the propagation chain
    via: list[tuple[str, int]] = field(default_factory=list)  # (file, line) of each helper step, ending at the sink
    helper: str = ""  # first helper the parameter was passed to


MAX_DEPTH = 3


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


class _Taint(ast.NodeVisitor):
    def __init__(self, params: list[str], aliases: dict[str, str], resolver: Resolver | None = None,
                 where: tuple[str, str | None] = ("", None), depth: int = 0) -> None:
        self.tainted: dict[str, int] = {p: 0 for p in params}  # name -> line where it became tainted
        self.hits: list[TaintHit] = []
        self.aliases = aliases
        self.source_text_hints: str = ""
        self.resolver = resolver
        self.where = where  # (file, enclosing class) of the function being analyzed
        self.depth = depth

    # -- helpers -----------------------------------------------------------
    def canon(self, name: str) -> str:
        head, _, rest = name.partition(".")
        if head in self.aliases:
            full = self.aliases[head]
            return f"{full}.{rest}" if rest else full
        return name

    def tainted_in(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted and isinstance(sub.ctx, ast.Load):
                return sub.id
        return None

    def constructed(self, node: ast.AST) -> bool:
        """Is the value built from pieces (f-string, concat, %/format) with taint?"""
        if isinstance(node, ast.JoinedStr):
            return self.tainted_in(node) is not None
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self.tainted_in(node) is not None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "join", "replace"):
            return self.tainted_in(node) is not None
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return True  # derived earlier; conservative
        return False

    def _targets(self, target: ast.AST) -> list[str]:
        out = []
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                out.append(sub.id)
        return out

    # -- propagation -------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        if self.tainted_in(node.value):
            for t in node.targets:
                for n in self._targets(t):
                    self.tainted.setdefault(n, node.lineno)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None and self.tainted_in(node.value):
            for n in self._targets(node.target):
                self.tainted.setdefault(n, node.lineno)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        if self.tainted_in(node.value):
            for n in self._targets(node.target):
                self.tainted.setdefault(n, node.lineno)

    def visit_For(self, node: ast.For) -> None:
        if self.tainted_in(node.iter):
            for n in self._targets(node.target):
                self.tainted.setdefault(n, node.lineno)
        self.generic_visit(node)

    def visit_withitem(self, node: ast.withitem) -> None:
        self.generic_visit(node)
        if node.optional_vars is not None and self.tainted_in(node.context_expr):
            for n in self._targets(node.optional_vars):
                self.tainted.setdefault(n, 0)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.generic_visit(node)
        if self.tainted_in(node.value):
            self.tainted.setdefault(node.target.id, node.lineno)

    # -- sinks -------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        name = self.canon(dotted(node.func))
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        first = node.args[0] if node.args else None
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        src = self.tainted_in(first) if first is not None else None

        def hit(kind: str, source: str | None) -> None:
            if source:
                self.hits.append(TaintHit(kind, node.lineno, node.col_offset + 1, name or method, source))

        if name in SHELL_FUNCS:
            hit("shell", src or self.tainted_in(kw.get("cmd")))
        elif name in SHELL_TRUE_FUNCS:
            shell = kw.get("shell")
            is_shell = isinstance(shell, ast.Constant) and shell.value is True
            arg = first if first is not None else kw.get("args")
            if is_shell:
                hit("shell", self.tainted_in(arg))
            else:
                hit("argv", self.tainted_in(arg))
        elif name in ARGV_FUNCS:
            hit("argv", self.tainted_in(ast.Tuple(elts=list(node.args), ctx=ast.Load())))
        elif name in EVAL_FUNCS:
            hit("eval", src)
        elif name in DESER_FUNCS or (name == "yaml.load" and not _safe_loader(kw)):
            hit("deser", src)
        elif name in PATH_FUNCS:
            hit("path", src or self.tainted_in(kw.get("file")) or self.tainted_in(kw.get("path")))
        elif method in ("read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "open") and isinstance(node.func, ast.Attribute):
            hit("path", self.tainted_in(node.func.value))
        elif name in URL_FUNCS or (method in URL_METHODS and isinstance(node.func, ast.Attribute)
                                   and any(s in dotted(node.func.value).lower() for s in ("session", "client", "http", "requests"))):
            url = first if first is not None else kw.get("url")
            if url is not None and _url_prefix_tainted(url, self):
                hit("url", self.tainted_in(url))
        elif method in SQL_METHODS and first is not None and self.constructed(first):
            hit("sql", src)
        elif name in TEMPLATE_FUNCS or method in TEMPLATE_METHODS:
            hit("template", src)
        elif self.resolver is not None:
            self._helper(node)

    def _helper(self, node: ast.Call) -> None:
        assert self.resolver is not None
        target = self.resolver.resolve(self.where[0], node.func, self.where[1])
        if target is None:
            return
        params = target.params()
        passed: list[tuple[str, str]] = []  # (helper parameter, tainted argument)
        for i, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred):
                break
            src = self.tainted_in(arg)
            if src and i < len(params):
                passed.append((params[i], src))
        for kw in node.keywords:
            src = self.tainted_in(kw.value)
            if src and kw.arg in params:
                passed.append((kw.arg, src))
        for param, src in passed:
            for h in self.resolver.summary(target, param, self.depth + 1):
                self.hits.append(TaintHit(h.kind, node.lineno, node.col_offset + 1, h.sink, src, h.sanitized,
                                          via=[(target.path, h.line), *h.via], helper=target.name))


def _safe_loader(kw: dict[str, ast.AST]) -> bool:
    loader = kw.get("Loader")
    return loader is not None and "Safe" in dotted(loader)


def _url_prefix_tainted(url: ast.AST, t: _Taint) -> bool:
    """Only report SSRF when the scheme/host part is attacker-controlled."""
    if isinstance(url, ast.Name):
        return url.id in t.tainted
    if isinstance(url, ast.JoinedStr) and url.values:
        head = url.values[0]
        return isinstance(head, ast.FormattedValue) and t.tainted_in(head) is not None
    if isinstance(url, ast.BinOp) and isinstance(url.op, ast.Add):
        return _url_prefix_tainted(url.left, t)
    return False


def import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def analyze_function(fn: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str], source: str,
                     resolver: Resolver | None = None, where: tuple[str, str | None] = ("", None)) -> list[TaintHit]:
    params = [a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs if a.arg not in ("self", "cls", "ctx", "context")]
    if fn.args.vararg:
        params.append(fn.args.vararg.arg)
    if fn.args.kwarg:
        params.append(fn.args.kwarg.arg)
    return _run(fn, params, aliases, source, resolver, where, 0)


def _run(fn: ast.FunctionDef | ast.AsyncFunctionDef, params: list[str], aliases: dict[str, str], source: str,
         resolver: Resolver | None, where: tuple[str, str | None], depth: int) -> list[TaintHit]:
    t = _Taint(params, aliases, resolver, where, depth)
    for stmt in fn.body:
        t.visit(stmt)
    body_src = ast.get_source_segment(source, fn) or ""
    out = []
    for h in t.hits:
        hints = SANITIZERS.get(h.kind, ())
        if any(s in body_src for s in hints):
            if h.kind in ("path", "url"):
                continue  # containment / allowlist check present: not reported
            h.sanitized = True  # quoting/validation present: reported with lower confidence
        h.path = sorted({ln for n, ln in t.tainted.items() if ln})
        out.append(h)
    return out


# -- helpers across the component -------------------------------------------------
@dataclass(frozen=True)
class Target:
    path: str
    fn: ast.FunctionDef | ast.AsyncFunctionDef
    cls: str | None

    @property
    def name(self) -> str:
        return f"{self.cls}.{self.fn.name}" if self.cls else self.fn.name

    def params(self) -> list[str]:
        names = [a.arg for a in self.fn.args.posonlyargs + self.fn.args.args]
        if self.cls and names and not any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in self.fn.decorator_list):
            names = names[1:]  # self / cls
        return names + [a.arg for a in self.fn.args.kwonlyargs]


@dataclass
class _Module:
    tree: ast.Module
    source: str
    aliases: dict[str, str]
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    classes: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    names: dict[str, tuple[str | None, str | None]]  # local name -> (module file, function name or None for a module)


class Resolver:
    """Finds the function a call refers to among one component's Python files,
    and summarizes which sinks each of its parameters reaches."""

    def __init__(self, sources: dict[str, str], root: str) -> None:
        self.sources = sources
        self.root = root
        self._modules: dict[str, _Module | None] = {}
        self._summaries: dict[tuple[str, str | None, str, str, int], list[TaintHit]] = {}
        self._active: set[tuple[str, str | None, str, str]] = set()

    def module(self, path: str) -> _Module | None:
        if path not in self._modules:
            self._modules[path] = self._load(path)
        return self._modules[path]

    def _load(self, path: str) -> _Module | None:
        source = self.sources.get(path)
        if source is None:
            return None
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return None
        functions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        classes = {c.name: {n.name: n for n in c.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
                   for c in tree.body if isinstance(c, ast.ClassDef)}
        here = posixpath.dirname(path)
        names: dict[str, tuple[str | None, str | None]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    local = a.asname or a.name.split(".")[0]
                    names[local] = (self._file(a.name if a.asname else a.name.split(".")[0], 0, here), None)
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    local = a.asname or a.name
                    as_module = self._file(f"{node.module}.{a.name}" if node.module else a.name, node.level, here)
                    if as_module:
                        names[local] = (as_module, None)
                    elif node.module:
                        names[local] = (self._file(node.module, node.level, here), a.name)
        return _Module(tree, source, import_aliases(tree), functions, classes, names)

    def _file(self, module: str, level: int, here: str) -> str | None:
        from ..correlate.links import py_module_paths  # avoid an import cycle at load time
        return next((p for p in py_module_paths(module, level, here, self.root) if p in self.sources), None)

    def resolve(self, path: str, func: ast.AST, cls: str | None) -> Target | None:
        mod = self.module(path)
        if mod is None:
            return None
        if isinstance(func, ast.Name):
            if func.id in mod.functions:
                return Target(path, mod.functions[func.id], None)
            file, name = mod.names.get(func.id, (None, None))
            other = self.module(file) if file and name else None
            if other is not None and name in other.functions:
                return Target(file, other.functions[name], None)  # type: ignore[arg-type]
            return None
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            head = func.value.id
            if head in ("self", "cls") and cls and func.attr in mod.classes.get(cls, {}):
                return Target(path, mod.classes[cls][func.attr], cls)
            file, name = mod.names.get(head, (None, None))
            other = self.module(file) if file and name is None else None
            if other is not None and func.attr in other.functions:
                return Target(file, other.functions[func.attr], None)  # type: ignore[arg-type]
        return None

    def summary(self, target: Target, param: str, depth: int) -> list[TaintHit]:
        """Sinks ``param`` of ``target`` reaches (lines in ``target.path``)."""
        if depth > MAX_DEPTH:
            return []
        key = (target.path, target.cls, target.fn.name, param)
        if key in self._active:
            return []  # recursion
        cached = self._summaries.get((*key, depth))
        if cached is not None:
            return cached
        mod = self.module(target.path)
        if mod is None:
            return []
        self._active.add(key)
        try:
            hits = _run(target.fn, [param], mod.aliases, mod.source, self, (target.path, target.cls), depth)
        finally:
            self._active.discard(key)
        self._summaries[(*key, depth)] = hits
        return hits


def enclosing_classes(tree: ast.Module) -> dict[int, str]:
    """Line of each method → name of its class (top-level classes)."""
    return {n.lineno: c.name for c in tree.body if isinstance(c, ast.ClassDef)
            for n in c.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def tool_functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Functions registered as MCP tools (decorated with *.tool / tool)."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                name = target.attr if isinstance(target, ast.Attribute) else target.id if isinstance(target, ast.Name) else ""
                if name in ("tool", "mcp_tool", "call_tool"):
                    out.append(node)
                    break
    return out
