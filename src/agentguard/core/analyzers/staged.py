"""AG-SKL-SE-010: a downloaded file is executed, in the same file or in another
file of the same skill (download-and-execute split across scripts).

Pure text analysis. A *download* writes a URL to a path (curl -o, wget -O,
Invoke-WebRequest -OutFile, certutil -urlcache, bitsadmin /transfer,
urllib.request.urlretrieve, a fetched body written with open(..., "wb") or
fs.writeFileSync). An *execution* runs that path directly, through an
interpreter (sh, bash, source, python, node, powershell -File, start), or
marks it executable (chmod +x, os.chmod 0o755). Downloads and executions are
linked across all scripts and markdown code of one component by comparing
normalized paths (home and temp directories, quotes, ``./``, separators).
"""

from __future__ import annotations

import posixpath
import urllib.parse
from dataclasses import dataclass
from typing import ClassVar

import regex

from ..artifacts import ArtifactText
from ..models import Evidence
from ..models.enums import ArtifactRole, ComponentKind, EvidenceKind, Severity
from ..redact import RedactedText
from ..textutil import TIMEOUT
from .base import Context

RULE = "AG-SKL-SE-010"
_ROLES = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference, ArtifactRole.script)
_KINDS = (ComponentKind.skill, ComponentKind.instruction_file, ComponentKind.command, ComponentKind.subagent)
_F = regex.IGNORECASE

_URL = regex.compile(r"https?://[^\s\"'`<>)]+", _F)
_TOKEN = regex.compile(r'"[^"]*"|\'[^\']*\'|[^\s"\']+')
# Command separators: && || ; | and a lone & (cmd.exe), but not 2>&1 or >&.
_SPLIT = regex.compile(r"\s*(?:&&|\|\||;|\||(?<![<>&])&(?![>&]))\s*")
_PREFIXES = {"sudo", "nohup", "exec", "time", "doas", "call"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "source", ".", "python", "python3", "node", "perl", "ruby", "deno", "bun"}
_PS = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_INLINE_CODE = regex.compile(r"`([^`\n]+)`")
_INTEGRITY = regex.compile(
    r"\b(?:sha256sum|sha512sum|shasum|Get-FileHash|certutil\s+-hashfile|gpg\s+--verify|cosign\s+verify(?:-blob)?|"
    r"minisign\s+-V|slsa-verifier|hashlib\.sha(?:256|512))\b", _F)

# Python / JavaScript forms.
_PY_ASSIGN = regex.compile(
    r"^\s*(\w+)\s*=\s*(?:os\.path\.expanduser\(\s*)?(?:(?:pathlib\.)?Path\(\s*)?(['\"])([^'\"\n]+)\2", _F | regex.MULTILINE)
_JS_ASSIGN = regex.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(['\"`])([^'\"`\n]+)\2", regex.MULTILINE)
_JS_JOIN = regex.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*path\.join\(\s*os\.homedir\(\)\s*,([^)\n]*)\)", regex.MULTILINE)
_PY_RETRIEVE = regex.compile(r"\burlretrieve\(\s*([^,\n]+?)\s*,\s*([^,)\n]+?)\s*[,)]")
_PY_OPEN_WB = regex.compile(r"\bopen\(\s*([^,\n]+?)\s*,\s*['\"](?:wb|bw|xb)['\"]")
_PY_FETCH = regex.compile(r"\b(?:requests|httpx)\.get\(|\burlopen\(|\burllib\.request\.")
_PY_CHMOD = regex.compile(r"\bos\.chmod\(\s*([^,\n]+?)\s*,\s*(0o?[0-7]+|stat\.S_IX\w+)")
_PY_EXEC = regex.compile(
    r"\b(?:subprocess\.(?:run|call|Popen|check_call|check_output)|os\.(?:system|startfile|exec\w*|spawn\w*))\(\s*\[?\s*([^,\]\)\n]+)")
_JS_WRITE = regex.compile(r"\bfs\.(?:writeFileSync|createWriteStream|promises\.writeFile|writeFile)\(\s*([^,)\n]+)")
_JS_FETCH = regex.compile(r"\bfetch\(\s*['\"`]https?://|\bhttps?\.get\(|\baxios\.get\(")
_JS_CHMOD = regex.compile(r"\bfs\.(?:chmodSync|chmod|promises\.chmod)\(\s*([^,\n]+?)\s*,\s*(0o?[0-7]+)")
_JS_EXEC = regex.compile(r"\b(?:execFile|execFileSync|spawn|spawnSync|exec|execSync)\(\s*([^,)\n]+)")


@dataclass(frozen=True)
class Event:
    kind: str          # download | exec | chmod
    path: str          # normalized
    raw: str
    url: str
    at: ArtifactText
    offset: int


def normalize_path(raw: str) -> str | None:
    p = raw.strip().strip("\"'`").strip()
    if not p or p in ("-", "/dev/null", "NUL") or p.startswith("-") or "://" in p:
        return None
    p = p.replace("\\", "/")
    for home in ("${HOME}", "$HOME", "%USERPROFILE%", "$env:USERPROFILE", "${env:USERPROFILE}"):
        if p.startswith(home):
            p = "~" + p[len(home):]
    for tmp in ("%TEMP%", "%TMP%", "$env:TEMP", "$env:TMP", "${TMPDIR}", "$TMPDIR"):
        if p.lower().startswith(tmp.lower()):
            p = "%TEMP%" + p[len(tmp):]
    while p.startswith("./"):
        p = p[2:]
    p = posixpath.normpath(p) if p not in ("~",) else p
    return p if p not in (".", "~", "/") else None


def _executable_mode(mode: str) -> bool:
    if "x" in mode and "+" in mode:
        return True
    m = mode.lower().removeprefix("0o").lstrip("0") or "0"
    return m.isdigit() and len(m) >= 3 and int(m[-3]) % 2 == 1


def _basename_of(url: str) -> str | None:
    name = posixpath.basename(urllib.parse.urlsplit(url).path)
    return name or None


def _tokens(cmd: str) -> list[str]:
    return [t[1:-1] if len(t) > 1 and t[0] == t[-1] and t[0] in "\"'" else t for t in _TOKEN.findall(cmd)]


def shell_events(cmdline: str) -> list[tuple[str, str, str]]:
    """(kind, raw path, url) events in one line of shell / cmd / PowerShell."""
    out: list[tuple[str, str, str]] = []
    for cmd in _SPLIT.split(cmdline):
        toks = _tokens(cmd)
        while toks and (toks[0].lower() in _PREFIXES or regex.fullmatch(r"\w+=\S*", toks[0])):
            toks = toks[1:]
        if not toks:
            continue
        head = posixpath.basename(toks[0].replace("\\", "/")).lower()
        url = next((t for t in toks if _URL.match(t)), "")
        if head in ("curl", "curl.exe") and url:
            dest = None
            for i, t in enumerate(toks):
                if (t in ("-o", "--output") or regex.fullmatch(r"-[a-zA-Z]*o", t)) and i + 1 < len(toks):
                    dest = toks[i + 1]
                elif t.startswith("--output="):
                    dest = t.split("=", 1)[1]
            if dest is None and any(t in ("-O", "--remote-name") or regex.fullmatch(r"-[a-zA-Z]*O[a-zA-Z]*", t) for t in toks):
                dest = _basename_of(url)
            if dest:
                out.append(("download", dest, url))
        elif head in ("wget", "wget.exe") and url:
            dest = None
            for i, t in enumerate(toks):
                attached = regex.fullmatch(r"-[a-zA-Z]*O(\S+)", t)
                if (t in ("-O", "--output-document") or regex.fullmatch(r"-[a-zA-Z]*O", t)) and i + 1 < len(toks):
                    dest = toks[i + 1]
                elif attached:  # -O- (stdout) or -Ofile
                    dest = attached.group(1)
                elif t.startswith("--output-document="):
                    dest = t.split("=", 1)[1]
            dest = dest if dest is not None else _basename_of(url)
            if dest and dest != "-":
                out.append(("download", dest, url))
        elif head in ("iwr", "invoke-webrequest", "start-bitstransfer") and url:
            for i, t in enumerate(toks):
                if t.lower() in ("-outfile", "-destination") and i + 1 < len(toks):
                    out.append(("download", toks[i + 1], url))
        elif head in ("certutil", "certutil.exe") and url and any(t.lower() == "-urlcache" for t in toks):
            i = toks.index(url)
            if i + 1 < len(toks):
                out.append(("download", toks[i + 1], url))
        elif head in ("bitsadmin", "bitsadmin.exe") and url:
            i = toks.index(url)
            if i + 1 < len(toks):
                out.append(("download", toks[i + 1], url))
        elif head == "chmod":
            mode = next((t for t in toks[1:] if not t.startswith("-")), "")
            if _executable_mode(mode):
                out.extend(("chmod", t, "") for t in toks[1:] if not t.startswith("-") and t != mode)
        elif head in _SHELLS:
            rest = [t for t in toks[1:] if not t.startswith("-")]
            if rest and not any(t in ("-c", "-m", "-e") for t in toks[1:2]):
                out.append(("exec", rest[0], ""))
        elif head in _PS:
            for i, t in enumerate(toks):
                if t.lower() in ("-file", "-f") and i + 1 < len(toks):
                    out.append(("exec", toks[i + 1], ""))
        elif head in ("start", "start-process", "saps", "open"):
            rest = [t for t in toks[1:] if not t.startswith(("-", "/")) and t != ""]
            if rest:
                out.append(("exec", rest[0], ""))
        elif head in ("cmd", "cmd.exe"):
            rest = [t for t in toks[1:] if t.lower() not in ("/c", "/k")]
            if rest:
                out.extend(shell_events(" ".join(rest)))
        elif toks[0][:1] in "/.~$%" or "/" in toks[0] or "\\" in toks[0]:
            out.append(("exec", toks[0], ""))
    return out


def _resolve(expr: str, env: dict[str, str]) -> str:
    e = expr.strip()
    lit = regex.fullmatch(r"(?:os\.path\.expanduser\(\s*)?(?:(?:pathlib\.)?Path\(\s*)?(['\"`])([^'\"`]+)\1\s*\)*(?:\.expanduser\(\))?", e)
    if lit:
        return lit.group(2)
    return env.get(e, e)


def _lines(at: ArtifactText) -> list[tuple[int, str]]:
    """(offset, text) of the lines that hold commands: every line of a script;
    fenced code and inline code spans of markdown."""
    text = at.text
    if at.artifact.role == ArtifactRole.script:
        out, pos = [], 0
        for line in text.split("\n"):
            out.append((pos, line))
            pos += len(line) + 1
        return out
    out = []
    for f in at.fence_list:
        pos = f.body_start
        for line in text[f.body_start:f.body_end].split("\n"):
            out.append((pos, line))
            pos += len(line) + 1
    try:
        for m in _INLINE_CODE.finditer(text, timeout=TIMEOUT):
            if not at.in_code(m.start()):
                out.append((m.start(1), m.group(1)))
    except TimeoutError:
        pass
    return out


def events_for(at: ArtifactText) -> list[Event]:
    events: list[Event] = []
    path = at.path.lower()
    text = at.text

    def add(kind: str, raw: str, url: str, offset: int) -> None:
        norm = normalize_path(raw)
        if norm:
            events.append(Event(kind, norm, raw, url, at, offset))

    if at.artifact.role == ArtifactRole.script and path.endswith(".py"):
        env = {m.group(1): m.group(3) for m in _PY_ASSIGN.finditer(text)}
        url = next(iter(_URL.findall(text)), "")
        for m in _PY_RETRIEVE.finditer(text):
            add("download", _resolve(m.group(2), env), _resolve(m.group(1), env), m.start())
        if _PY_FETCH.search(text) and url:
            for m in _PY_OPEN_WB.finditer(text):
                add("download", _resolve(m.group(1), env), url, m.start())
        for m in _PY_CHMOD.finditer(text):
            if m.group(2).startswith("stat.") or _executable_mode(m.group(2)):
                add("chmod", _resolve(m.group(1), env), "", m.start())
        for m in _PY_EXEC.finditer(text):
            target = _resolve(m.group(1), env)
            for kind, raw, u in shell_events(target) or [("exec", target, "")]:
                add(kind, raw, u, m.start())
        return events
    if at.artifact.role == ArtifactRole.script and path.endswith((".js", ".mjs", ".cjs", ".ts")):
        env = {m.group(1): m.group(3) for m in _JS_ASSIGN.finditer(text)}
        for m in _JS_JOIN.finditer(text):
            parts = [p.strip().strip("'\"`") for p in m.group(2).split(",") if p.strip()]
            env[m.group(1)] = "~/" + "/".join(parts)
        url = next(iter(_URL.findall(text)), "")
        if _JS_FETCH.search(text) and url:
            for m in _JS_WRITE.finditer(text):
                add("download", _resolve(m.group(1), env), url, m.start())
        for m in _JS_CHMOD.finditer(text):
            if _executable_mode(m.group(2)):
                add("chmod", _resolve(m.group(1), env), "", m.start())
        for m in _JS_EXEC.finditer(text):
            target = _resolve(m.group(1), env)
            for kind, raw, u in shell_events(target) or [("exec", target, "")]:
                add(kind, raw, u, m.start())
        return events
    for offset, line in _lines(at):
        for kind, raw, url in shell_events(line):
            add(kind, raw, url, offset + max(0, line.find(raw)))
    return events


class StagedExecutionAnalyzer:
    id: ClassVar[str] = "skill.staged"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (RULE,)

    def run(self, ctx: Context) -> None:
        if not ctx.rule_enabled(RULE):
            return
        rule = ctx.pack.rule(RULE)
        params = rule.match.params if hasattr(rule.match, "params") else {}
        allow = regex.compile(params["allow_hosts"], _F) if params.get("allow_hosts") else None
        by_comp: dict[str, list[ArtifactText]] = {}
        for at in ctx.texts(*(r.value for r in _ROLES)):
            by_comp.setdefault(at.artifact.component_id, []).append(at)
        for comp in ctx.inventory.of_kind(*_KINDS):
            texts = by_comp.get(comp.id, [])
            events = [e for at in texts for e in events_for(at)]
            downloads = [e for e in events if e.kind == "download"]
            if not downloads:
                continue
            verified = any(_INTEGRITY.search(at.text) for at in texts)
            done: set[str] = set()
            for dl in downloads:
                if dl.path in done:
                    continue
                runs = [e for e in events if e.kind == "exec" and e.path == dl.path]
                marks = [e for e in events if e.kind == "chmod" and e.path == dl.path]
                target = (runs or marks or [None])[0]
                if target is None:
                    continue
                done.add(dl.path)
                severity: Severity | None = None if runs else Severity.high
                host = urllib.parse.urlsplit(dl.url).hostname or dl.url
                note = ""
                if allow is not None and allow.search(dl.url):
                    severity, note = Severity.low, " The host is a known vendor installer."
                elif verified:
                    severity, note = Severity.medium, " An integrity check (checksum or signature) appears in the same skill."
                split = target.at.path != dl.at.path
                dl_span, tg_span = dl.at.span(dl.offset), target.at.span(target.offset)
                how = "executed" if runs else "made executable"
                where = f"in {target.at.path}" if split else "in the same file"
                ctx.emit(
                    RULE,
                    component_ids=comp.id,
                    span=tg_span,
                    snippet=target.at.line_text(target.offset).strip(),
                    match=f"{comp.id}:{dl.path}",
                    kind=EvidenceKind.metadata,
                    detail=f"{how}: {dl.path}",
                    severity=severity,
                    related=[dl_span],
                    extra_evidence=[Evidence(kind=EvidenceKind.metadata, location=dl_span,
                                             snippet=RedactedText.of(dl.at.line_text(dl.offset).strip()),
                                             detail=f"downloaded from {host} to {dl.path}")],
                    message=(f"A file downloaded from {host} to {dl.path} ({dl.at.path}:{dl_span.start_line}) is {how} "
                             f"{where} (line {tg_span.start_line}){' — the download and the execution are split across files' if split else ''}.{note}"),
                )


__all__ = ["StagedExecutionAnalyzer", "events_for", "normalize_path", "shell_events"]
