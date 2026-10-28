"""Links between the files of one component, so evidence split across files can
be correlated (AG-SKL-CRED-010).

Pure text and ``ast`` analysis: nothing is imported or executed. A link says
data can move from one file to another:

- ``file``: one file writes a path and another file names the same path (a
  temp or cache file used as a relay). Paths are compared after normalization
  (home and temp directories, quotes, ``./``); Python paths built with
  ``Path.home() / ...``, ``os.path.join`` and ``expanduser`` are resolved.
- ``runs``: a script runs another script of the component (also through
  ``$(dirname "$0")``), so data can pass through arguments, the environment
  or output. Data can flow either way.
- ``import``: a script imports a module of the component (Python ``import`` /
  ``from``, relative or sibling; JavaScript ``require`` / ``import`` of a
  ``./`` path). Data can flow either way.

Markdown is only ever an end of a chain: a SKILL.md that runs two scripts does
not move data between them.
"""

from __future__ import annotations

import ast
import posixpath
import shlex
from collections import deque
from dataclasses import dataclass

import regex

from ..analyzers.staged import _JS_JOIN, _JS_WRITE, _SPLIT, _lines, normalize_path, shell_events
from ..artifacts import ArtifactText
from ..models.enums import ArtifactRole

MAX_FILES = 200   # files per component; above this, links are not traced (reported as a limit event)
MAX_HOPS = 3

_MARKDOWN = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference)
_CODE = (ArtifactRole.script, ArtifactRole.source_code)

_DIRNAME = regex.compile(
    r"\$\(\s*dirname\s+(?:--\s+)?[\"']?\$\{?(?:0|BASH_SOURCE(?:\[0\])?)\}?[\"']?\s*\)|\$\{0%/\*\}|\$\{BASH_SOURCE(?:\[0\])?%/\*\}")
_DIR_VAR = regex.compile(r"^\s*(?:export\s+|local\s+|readonly\s+)?(\w+)=[\"']?(?:\$\(\s*cd\s+[\"']?)?@here\b", regex.MULTILINE)
_REDIRECT = regex.compile(r"^(?:\d|&)?>>?(?!&)(.*)$")
_SUBST = regex.compile(r"\$\(([^()]*)\)|`([^`]*)`")
_JS_STRING = regex.compile(r"(['\"`])([^'\"`\n]{1,200})\1")
_JS_IMPORT = regex.compile(r"(?:\brequire\(\s*|\bfrom\s+|\bimport\s*\(?\s*)(['\"])(\.{1,2}/[^'\"\n]+)\1")
_JS_EXTS = ("", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", "/index.js", "/index.ts")
_HERE = "@here"


@dataclass(frozen=True)
class Link:
    kind: str        # file | runs | import
    src: str         # path the data leaves
    dst: str         # path the data reaches
    via: str         # the shared path, or the target as written
    src_offset: int
    dst_offset: int


@dataclass
class _Facts:
    writes: list[tuple[str, int]]      # (normalized path, offset)
    mentions: list[tuple[str, int]]
    runs: list[tuple[str, int]]        # (target as written, offset)
    imports: list[tuple[list[str], str, int]]  # (candidate paths, as written, offset)


# -- shell and markdown --------------------------------------------------------
def _words(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, comments=True, posix=True)
    except ValueError:
        return [w.strip("\"'") for w in cmd.split()]


def _here_lines(at: ArtifactText) -> list[tuple[int, str]]:
    lines = [(off, _DIRNAME.sub(_HERE, line)) for off, line in _lines(at)]
    dirvars = {m.group(1) for _, line in lines for m in _DIR_VAR.finditer(line)}
    if dirvars:
        var = regex.compile(r"\$\{?(" + "|".join(sorted(dirvars)) + r")\}?\b")
        lines = [(off, var.sub(_HERE, line)) for off, line in lines]
    return lines


def _commands(line: str) -> list[str]:
    """The line with each command substitution replaced by a word, followed by
    the substituted commands themselves (innermost first)."""
    inner: list[str] = []
    for _ in range(8):
        m = _SUBST.search(line)
        if m is None:
            break
        inner.append(m.group(1) if m.group(1) is not None else m.group(2))
        line = line[:m.start()] + "$SUB" + line[m.end():]
    return [line, *inner]


def _shell_facts(at: ArtifactText, f: _Facts) -> None:
    for off, text in _here_lines(at):
        for line in _commands(text):
            _shell_line(line, off, f)


def _shell_line(line: str, off: int, f: _Facts) -> None:
    for cmd in _SPLIT.split(line):
        words = _words(cmd)
        for i, w in enumerate(words):
            m = _REDIRECT.match(w)
            if m:
                target = m.group(1) or (words[i + 1] if i + 1 < len(words) else "")
                _add(f.writes, target, off)
                continue
            mention = w.split("=", 1)[1] if w.startswith("--") and "=" in w else w
            mention = mention.split("@", 1)[1] if "@" in mention and "://" not in mention else mention
            _add(f.mentions, mention.lstrip("<"), off)
        while words and regex.fullmatch(r"\w+=.*", words[0]):
            words = words[1:]
        if not words:
            continue
        head = posixpath.basename(words[0]).lower()
        args = [w for w in words[1:] if not w.startswith("-")]
        if head == "tee":
            for a in args:
                _add(f.writes, a, off)
        elif head in ("cp", "mv", "install") and len(args) >= 2:
            _add(f.writes, args[-1], off)
        elif head == "tar" and len(words) > 2 and "c" in words[1] and "f" in words[1]:
            _add(f.writes, words[2], off)
        elif head == "zip" and args:
            _add(f.writes, args[0], off)
    for kind, raw, _url in shell_events(line):
        if kind == "exec":
            f.runs.append((raw, off))


# -- Python ------------------------------------------------------------------------
def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class _PyPaths:
    """Resolves Python expressions that build a file path to a string."""

    def __init__(self, tree: ast.Module) -> None:
        self.env: dict[str, ast.AST] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        self.env.setdefault(t.id, node.value)

    def value(self, node: ast.AST | None, depth: int = 0) -> str | None:
        if node is None or depth > 8:
            return None
        v = self._value(node, depth + 1)
        return v if v is None or len(v) <= 300 else None

    def _value(self, node: ast.AST, d: int) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.value(self.env.get(node.id), d)
        if isinstance(node, ast.JoinedStr):
            parts = [self.value(v.value if isinstance(v, ast.FormattedValue) else v, d) for v in node.values]
            return None if None in parts else "".join(p for p in parts if p is not None)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            left, right = self.value(node.left, d), self.value(node.right, d)
            if left is None or right is None:
                return None
            return posixpath.join(left, right) if isinstance(node.op, ast.Div) else left + right
        if isinstance(node, ast.Subscript) and _dotted(node.value) == "os.environ":
            key = self.value(node.slice, d)
            return "~" if key in ("HOME", "USERPROFILE") else "%TEMP%" if key in ("TMPDIR", "TEMP", "TMP") else None
        if not isinstance(node, ast.Call):
            return None
        name = _dotted(node.func)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        args = [self.value(a, d) for a in node.args]
        if name.endswith(("Path.home", "os.path.expanduser")) and (not args or args == ["~"]):
            return "~"
        if name in ("tempfile.gettempdir", "gettempdir"):
            return "%TEMP%"
        if name in ("os.getenv", "os.environ.get") and args:
            return "~" if args[0] in ("HOME", "USERPROFILE") else None
        if name in ("os.path.expanduser", "expanduser", "os.path.abspath", "os.path.realpath") and len(args) == 1:
            return args[0]
        if name in ("os.path.join", "posixpath.join", "Path", "pathlib.Path", "PurePath") and args and None not in args:
            return posixpath.join(*[a for a in args if a is not None])
        if method in ("expanduser", "resolve", "absolute") and isinstance(node.func, ast.Attribute):
            return self.value(node.func.value, d)
        if method == "joinpath" and isinstance(node.func, ast.Attribute) and None not in args:
            base = self.value(node.func.value, d)
            return posixpath.join(base, *[a for a in args if a is not None]) if base is not None else None
        return None


def _write_mode(call: ast.Call, at: int) -> bool:
    mode = call.args[at] if len(call.args) > at else next((k.value for k in call.keywords if k.arg == "mode"), None)
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax")


def _py_facts(at: ArtifactText, f: _Facts, root: str) -> None:
    try:
        tree = ast.parse(at.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return
    starts = [0]
    for line in at.text.split("\n"):
        starts.append(starts[-1] + len(line) + 1)

    def off(node: ast.AST) -> int:
        line = getattr(node, "lineno", 1)
        return starts[min(line, len(starts)) - 1]

    paths = _PyPaths(tree)
    here = posixpath.dirname(at.path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            target: ast.AST | None = None
            if name in ("open", "io.open", "codecs.open") and node.args and _write_mode(node, 1):
                target = node.args[0]
            elif method in ("write_text", "write_bytes") and isinstance(node.func, ast.Attribute):
                target = node.func.value
            elif method == "open" and isinstance(node.func, ast.Attribute) and _write_mode(node, 0):
                target = node.func.value
            elif name in ("shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move", "os.rename", "os.replace",
                          "shutil.make_archive") and len(node.args) >= 2:
                target = node.args[0] if name == "shutil.make_archive" else node.args[1]
            if target is not None:
                _add(f.writes, paths.value(target) or "", off(node))
            v = paths.value(node)
            if v is not None:
                _add(f.mentions, v, off(node))
        elif isinstance(node, (ast.Constant, ast.BinOp)):
            v = paths.value(node)
            if v is not None:
                _add(f.mentions, v, off(node))
        elif isinstance(node, ast.Import):
            for a in node.names:
                f.imports.append((py_module_paths(a.name, 0, here, root), a.name, off(node)))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                f.imports.append((py_module_paths(node.module, node.level, here, root), node.module, off(node)))
            if node.level:
                for a in node.names:
                    mod = f"{node.module}.{a.name}" if node.module else a.name
                    f.imports.append((py_module_paths(mod, node.level, here, root), mod, off(node)))


def py_module_paths(module: str, level: int, here: str, root: str) -> list[str]:
    rel = module.replace(".", "/")
    if level:
        base = here
        for _ in range(level - 1):
            base = posixpath.dirname(base)
        bases = [base]
    else:
        bases = [here, root, posixpath.join(root, "src")]
    out = []
    for b in bases:
        p = posixpath.normpath(posixpath.join(b, rel)) if b else posixpath.normpath(rel)
        out += [f"{p}.py", f"{p}/__init__.py"]
    return out


# -- JavaScript / TypeScript ---------------------------------------------------------
def _js_facts(at: ArtifactText, f: _Facts) -> None:
    text = at.text
    env = {m.group(1): "~/" + "/".join(p.strip().strip("'\"`") for p in m.group(2).split(",") if p.strip())
           for m in _JS_JOIN.finditer(text)}
    for m in _JS_WRITE.finditer(text):
        expr = m.group(1).strip()
        _add(f.writes, env.get(expr, expr), m.start())
    for name, value in env.items():
        for m in regex.finditer(r"\b" + regex.escape(name) + r"\b", text):
            _add(f.mentions, value, m.start())
    for m in _JS_STRING.finditer(text):
        _add(f.mentions, m.group(2), m.start())
    here = posixpath.dirname(at.path)
    for m in _JS_IMPORT.finditer(text):
        spec = m.group(2)
        f.imports.append((js_module_paths(spec, here), spec, m.start()))
    for m in regex.finditer(r"\b(?:execFile|execFileSync|spawn|spawnSync|exec|execSync|fork)\(\s*(['\"`])([^'\"`\n]+)\1",
                            text):
        for kind, raw, _url in shell_events(m.group(2)) or [("exec", m.group(2), "")]:
            if kind == "exec":
                f.runs.append((raw, m.start()))


def js_module_paths(spec: str, here: str) -> list[str]:
    """Files a relative JavaScript/TypeScript import specifier may refer to
    (``./lib/run.js`` is also ``./lib/run.ts`` when compiled from TypeScript)."""
    base = posixpath.normpath(posixpath.join(here, spec))
    stem = regex.sub(r"\.(?:js|mjs|cjs)$", "", base)
    return [base + e for e in _JS_EXTS] + [stem + e for e in (".ts", ".mts", ".cts")]


# -- shared ------------------------------------------------------------------------
def _add(out: list[tuple[str, int]], raw: str, offset: int) -> None:
    if not raw or len(raw) > 300 or "\n" in raw or " " in raw.strip() or "${" in raw or "$(" in raw:
        return
    norm = normalize_path(raw)
    if norm and ("/" in norm or "." in norm) and not norm.startswith("@"):
        out.append((norm, offset))


def facts(at: ArtifactText, root: str) -> _Facts:
    f = _Facts([], [], [], [])
    lang = (at.artifact.language or "").lower()
    path = at.path.lower()
    if at.artifact.role in _CODE and (lang == "python" or path.endswith(".py")):
        _py_facts(at, f, root)
    elif at.artifact.role in _CODE and (lang in ("javascript", "typescript") or path.endswith((".js", ".mjs", ".cjs", ".ts"))):
        _js_facts(at, f)
    else:
        _shell_facts(at, f)
    return f


def _target(raw: str, at: ArtifactText, root: str, known: set[str]) -> str | None:
    here = posixpath.dirname(at.path)
    raw = raw.strip("\"'")
    if raw.startswith(_HERE):
        raw = here + raw[len(_HERE):]
    norm = normalize_path(raw)
    if not norm:
        return None
    for cand in (norm, posixpath.normpath(posixpath.join(here, norm)), posixpath.normpath(posixpath.join(root, norm))):
        if cand in known and cand != at.path:
            return cand
    if "/" not in norm:
        same = [p for p in known if posixpath.basename(p) == norm and p != at.path]
        if len(same) == 1:
            return same[0]
    return None


def component_links(texts: list[ArtifactText], root: str) -> list[Link]:
    """Every link between the given files of one component, in a stable order."""
    known = {at.path for at in texts}
    by_path = {at.path: facts(at, root) for at in texts}
    links: set[Link] = set()
    writers: dict[str, list[tuple[str, int]]] = {}
    for path, f in by_path.items():
        for norm, off in f.writes:
            writers.setdefault(norm, []).append((path, off))
    for path, f in by_path.items():
        at = next(t for t in texts if t.path == path)
        for norm, off in f.mentions:
            for wpath, woff in writers.get(norm, []):
                if wpath != path:
                    links.add(Link("file", wpath, path, norm, woff, off))
        for raw, off in f.runs:
            dst = _target(raw, at, root, known)
            if dst:
                links.add(Link("runs", path, dst, raw.strip("\"'"), off, 0))
        for cands, spec, off in f.imports:
            dst = next((c for c in cands if c in known and c != path), None)
            if dst:
                links.add(Link("import", path, dst, spec, off, 0))
    return sorted(links, key=lambda k: (k.src, k.dst, k.kind, k.via, k.src_offset, k.dst_offset))


def chain(links: list[Link], start: str, goals: set[str], markdown: set[str]) -> list[tuple[Link, bool]] | None:
    """Shortest chain from ``start`` to any of ``goals``: (link, followed forward)
    steps. At most MAX_HOPS links, at most one ``runs`` link, and no markdown
    file in the middle."""
    adj: dict[str, list[tuple[str, Link, bool]]] = {}
    for k in links:
        adj.setdefault(k.src, []).append((k.dst, k, True))
        if k.kind in ("runs", "import"):
            adj.setdefault(k.dst, []).append((k.src, k, False))
    queue: deque[tuple[str, list[tuple[Link, bool]]]] = deque([(start, [])])
    seen = {(start, 0)}
    while queue:
        node, path = queue.popleft()
        if len(path) >= MAX_HOPS:
            continue
        if path and node in markdown:
            continue
        for nxt, link, forward in adj.get(node, []):
            runs = sum(1 for k, _ in path if k.kind == "runs") + (link.kind == "runs")
            if runs > 1 or nxt == start or any(nxt in (k.src, k.dst) for k, _ in path):
                continue
            steps = [*path, (link, forward)]
            if nxt in goals:
                return steps
            if (nxt, runs) not in seen:
                seen.add((nxt, runs))
                queue.append((nxt, steps))
    return None


__all__ = ["MAX_FILES", "MAX_HOPS", "Link", "chain", "component_links", "facts", "js_module_paths", "py_module_paths"]
