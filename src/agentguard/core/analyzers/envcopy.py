"""Environment copies that are only handed to a child process.

``env = os.environ.copy(); env["X"] = "1"; subprocess.run(cmd, env=env)`` is
how programs set a variable for a subprocess; the environment never leaves the
machine. Only copies whose every use is recognised as child-process plumbing
are exempted from ENV_DUMP; anything else (printing, serializing, iterating,
passing to an unknown call) stays an environment dump. Unparseable code gets
no exemption.
"""

from __future__ import annotations

import ast

import regex

from ..textutil import TIMEOUT
from .heuristics import ENV_DUMP, finditer

_MUTATORS = {"update", "setdefault", "pop", "get", "copy"}


def _is_environ(n: ast.AST) -> bool:
    return (isinstance(n, ast.Attribute) and n.attr == "environ" and isinstance(n.value, ast.Name) and n.value.id == "os") or (
        isinstance(n, ast.Name) and n.id == "environ")


def _is_env_copy(n: ast.AST) -> bool:
    if _is_environ(n):
        return True
    if isinstance(n, ast.Call):
        f = n.func
        if isinstance(f, ast.Attribute) and f.attr == "copy" and _is_environ(f.value) and not n.args:
            return True
        if isinstance(f, ast.Name) and f.id == "dict" and len(n.args) == 1 and _is_environ(n.args[0]):
            return True
    if isinstance(n, ast.Dict):
        return any(k is None and _is_environ(v) for k, v in zip(n.keys, n.values))
    if isinstance(n, ast.DictComp) and len(n.generators) == 1:
        it = n.generators[0].iter                             # {k: v for k, v in os.environ.items() if ...}
        return (isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and it.func.attr == "items"
                and _is_environ(it.func.value))
    return False


class _PyEnv:
    def __init__(self, tree: ast.Module) -> None:
        self.parent: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for ch in ast.iter_child_nodes(node):
                self.parent[ch] = node
        self.tree = tree

    def _scope(self, node: ast.AST) -> ast.AST:
        p = self.parent.get(node)
        while p is not None and not isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)):
            p = self.parent.get(p)
        return p or self.tree

    def _env_kw(self, node: ast.AST) -> bool:
        p = self.parent.get(node)
        return isinstance(p, ast.keyword) and p.arg == "env"

    def flows_to_child(self, node: ast.AST, depth: int = 0) -> bool:
        if depth > 3:
            return False
        if self._env_kw(node):
            return True
        p = self.parent.get(node)
        if isinstance(p, ast.Dict) and node in p.values and p.keys[p.values.index(node)] is None:
            return self.flows_to_child(p, depth + 1)          # {**env, "A": "1"}
        if isinstance(p, ast.Return):
            return self._returned_to_child(p, depth)
        if isinstance(p, (ast.Assign, ast.AnnAssign)):
            targets = p.targets if isinstance(p, ast.Assign) else [p.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                return self._var_to_child(targets[0].id, self._scope(p), depth)
        return False

    def _var_to_child(self, name: str, scope: ast.AST, depth: int) -> bool:
        sunk = False
        for n in ast.walk(scope):
            if not (isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)):
                continue
            if self._scope(n) is not scope:
                return False                                  # captured by a nested function: unknown use
            p = self.parent.get(n)
            if isinstance(p, ast.Subscript) and p.value is n:
                continue                                      # env["X"] = ..., env["X"], del env["X"]
            if isinstance(p, ast.Attribute) and p.attr in _MUTATORS and isinstance(self.parent.get(p), ast.Call):
                continue                                      # env.update(...), env.get(...)
            if isinstance(p, ast.Compare) and n in p.comparators:
                continue                                      # "X" in env
            if self.flows_to_child(n, depth + 1):
                sunk = True
                continue
            return False
        return sunk

    def _returned_to_child(self, ret: ast.Return, depth: int) -> bool:
        fn = self._scope(ret)
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        calls = [n for n in ast.walk(self.tree) if isinstance(n, ast.Call) and (
            (isinstance(n.func, ast.Name) and n.func.id == fn.name) or (isinstance(n.func, ast.Attribute) and n.func.attr == fn.name))]
        return bool(calls) and all(self.flows_to_child(c, depth + 1) for c in calls)


def _offsets(text: str) -> tuple[list[str], list[int]]:
    lines = text.splitlines(keepends=True)
    starts, pos = [], 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln)
    return lines, starts


def _char_off(lines: list[str], starts: list[int], lineno: int, byte_col: int) -> int:
    if lineno - 1 >= len(lines):
        return starts[-1] if starts else 0
    ln = lines[lineno - 1]
    return starts[lineno - 1] + len(ln.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))


def _py_child_spans(text: str) -> list[tuple[int, int]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    env = _PyEnv(tree)
    lines, starts = _offsets(text)
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not _is_env_copy(node):
            continue
        p = env.parent.get(node)
        if p is not None and _is_env_copy(p) or (isinstance(p, ast.Attribute) and isinstance(env.parent.get(p), ast.Call)
                                               and _is_env_copy(env.parent[p])):
            continue                                          # the enclosing copy expression decides
        try:
            if env.flows_to_child(node):
                spans.append((_char_off(lines, starts, node.lineno, node.col_offset),
                              _char_off(lines, starts, node.end_lineno or node.lineno, node.end_col_offset or 0)))
        except RecursionError:
            continue
    return spans


_JS_COPY = regex.compile(r"\{\s*\.\.\.process\.env\b|\bObject\.assign\(\s*\{\}\s*,\s*process\.env\s*\)")
_JS_ASSIGN = regex.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$")


def _js_child_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for m in finditer(_JS_COPY, text):
        ls = text.rfind("\n", 0, m.start()) + 1
        before = text[ls : m.start()]
        if regex.search(r"\benv\s*:\s*$", before, timeout=TIMEOUT):
            spans.append(m.span())                            # spawn(cmd, args, { env: { ...process.env, X } })
            continue
        a = _JS_ASSIGN.search(before, timeout=TIMEOUT)
        if a and _js_var_to_child(text, a.group(1), m.end()):
            spans.append(m.span())
    return spans


def _js_var_to_child(text: str, name: str, after: int) -> bool:
    n = regex.escape(name)
    sink = False
    for u in regex.finditer(rf"(?<![\w$.]){n}(?![\w$])", text[after:], timeout=TIMEOUT):
        s = after + u.start()
        ls = text.rfind("\n", 0, s) + 1
        pre, post = text[ls:s], text[s + len(name) : s + len(name) + 40]
        if regex.match(r"\s*(?:\[[^\]\n]*\]|\.\w+)\s*=(?!=)", post) or regex.search(r"\bdelete\s+$", pre):
            continue                                          # env.X = "1"; env["X"] = "1"; delete env.X
        if regex.search(r"\benv\s*:\s*$", pre) or regex.search(r"\breturn\s+$", pre) or (
                name == "env" and regex.search(r"[{,]\s*$", pre) and regex.match(r"\s*[,}]", post)):
            sink = True                                       # { env: e }, { env }, return e
            continue
        return False
    return sink


def child_env_spans(text: str, language: str | None) -> list[tuple[int, int]]:
    """Character spans of ``text`` holding an environment copy that is only
    handed to a child process."""
    if language == "python":
        return _py_child_spans(text)
    if language in ("javascript", "typescript"):
        return _js_child_spans(text)
    return []


# A copy written straight into an env= keyword / env: option on the same line
# (also recognised in Markdown snippets and unparseable code).
# A keyword argument (`f(x, env=...)`, or `env=` opening a continuation line) or
# an object option (`{ env: ... }`); not an assignment such as `env = os.environ.copy()`.
_INLINE_ENV_ARG = regex.compile(
    r"(?:(?:^|[(,{])\s*env\s*:\s*|(?:^|[(,])\s*env=)"
    r"(?:dict\(\s*|\{\s*(?:\*\*|\.\.\.)\s*|Object\.assign\(\s*\{\}\s*,\s*)?$")


def env_dumps(text: str, language: str | None) -> list[regex.Match[str]]:
    """ENV_DUMP matches in ``text`` minus child-process environment copies."""
    hits = finditer(ENV_DUMP, text)
    if not hits:
        return hits
    child = child_env_spans(text, language)
    out = []
    for m in hits:
        if any(a <= m.start() < b for a, b in child):
            continue
        prefix = text[text.rfind("\n", 0, m.start()) + 1 : m.start()]
        if _INLINE_ENV_ARG.search(prefix, timeout=TIMEOUT):
            continue
        out.append(m)
    return out
