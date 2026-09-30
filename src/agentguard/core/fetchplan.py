"""Choosing which files of a remote repository to fetch.

A repository listing (e.g. GitHub's recursive tree) can be far larger than
what the analyzers use. ``plan_fetch`` keeps the files some analyzer reads,
orders them so skills and configuration come first, applies the load limits,
and records everything it leaves out as ``LimitEvent``s so the report can say
what was not scanned. Pure and deterministic: same listing → same plan.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .models import LimitEvent, LoadLimits

TEXT_EXTENSIONS = (
    ".md", ".mdc", ".markdown", ".mdx", ".txt",
    ".json", ".jsonc", ".toml", ".yaml", ".yml", ".cfg", ".ini",
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
    ".sh", ".bash", ".zsh", ".ksh", ".ps1", ".psm1", ".bat", ".cmd",
    ".rb", ".pl", ".php", ".go", ".rs", ".lua", ".applescript", ".vbs",
    ".html", ".htm",
)
KNOWN_NAMES = ("dockerfile", "makefile", "requirements.txt", "setup.py", "setup.cfg", "agentguard.lock")
# Large, generated, and not read by any analyzer.
SKIP_NAMES = (
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "uv.lock", "cargo.lock", "gemfile.lock", "composer.lock", "pipfile.lock", "bun.lockb",
)


class RemoteEntry(BaseModel):
    path: str
    type: str = "blob"        # blob | tree | commit (submodule)
    mode: str = "100644"
    size: int | None = None


class FetchPlan(BaseModel):
    fetch: list[RemoteEntry] = Field(default_factory=list)
    events: list[LimitEvent] = Field(default_factory=list)
    not_relevant: int = 0     # files no analyzer reads (images, lockfiles, …)
    fetch_bytes: int = 0


def _within(path: str, subpath: str) -> bool:
    return not subpath or path == subpath or path.startswith(subpath.rstrip("/") + "/")


def _dir(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _priority(path: str, skill_dirs: set[str]) -> int:
    lower = path.lower()
    base = lower.rsplit("/", 1)[-1]
    if base == "skill.md":
        return 0
    if any(path == d or path.startswith(d + "/") for d in skill_dirs if d) or ("" in skill_dirs):
        return 1
    if lower.endswith((".md", ".mdc", ".markdown", ".mdx")) or lower.endswith((".json", ".jsonc", ".toml", ".yaml", ".yml")):
        return 2
    if base in KNOWN_NAMES:
        return 3
    return 4


def relevant(path: str) -> bool:
    lower = path.lower()
    base = lower.rsplit("/", 1)[-1]
    if base in SKIP_NAMES:
        return False
    return base in KNOWN_NAMES or lower.endswith(TEXT_EXTENSIONS) or base.startswith(".mcp")


def plan_fetch(
    entries: list[RemoteEntry],
    limits: LoadLimits,
    *,
    subpath: str = "",
    max_files: int | None = None,
    truncated: bool = False,
) -> FetchPlan:
    plan = FetchPlan()
    subpath = subpath.strip("/")
    max_files = min(max_files or limits.max_files, limits.max_files)
    if truncated:
        plan.events.append(LimitEvent(kind="listing_truncated", path=subpath or ".",
                                      detail="the repository listing was truncated by the host; some files were not seen"))
    excluded = {d.lower() for d in limits.excluded_dirs}
    files: list[RemoteEntry] = []
    for e in sorted(entries, key=lambda x: x.path):
        if not _within(e.path, subpath):
            continue
        if any(seg.lower() in excluded for seg in e.path.split("/")[:-1]):
            continue
        if e.type == "commit":
            plan.events.append(LimitEvent(kind="submodule", path=e.path, detail="git submodule not fetched"))
            continue
        if e.type != "blob":
            continue
        if e.mode == "120000":
            plan.events.append(LimitEvent(kind="symlink", path=e.path))
            continue
        if e.path.count("/") >= limits.max_depth:
            plan.events.append(LimitEvent(kind="too_deep", path=e.path))
            continue
        files.append(e)

    # Everything inside a skill directory is kept (bundled binaries and archives are findings too).
    skill_dirs = {_dir(f.path) for f in files if f.path.lower().rsplit("/", 1)[-1] == "skill.md"}
    chosen: list[RemoteEntry] = []
    for f in files:
        in_skill = any(f.path.startswith(d + "/") for d in skill_dirs if d) or ("" in skill_dirs)
        if not (in_skill or relevant(f.path)):
            plan.not_relevant += 1
            continue
        if f.size is not None and f.size > limits.max_file_bytes:
            plan.events.append(LimitEvent(kind="too_large", path=f.path, detail=f"{f.size} bytes > {limits.max_file_bytes}"))
            continue
        chosen.append(f)

    chosen.sort(key=lambda f: (_priority(f.path, skill_dirs), f.path))
    dropped = 0
    for f in chosen:
        size = f.size or 0
        if len(plan.fetch) >= max_files or plan.fetch_bytes + size > limits.max_total_bytes:
            dropped += 1
            continue
        plan.fetch.append(f)
        plan.fetch_bytes += size
    if dropped:
        plan.events.append(LimitEvent(kind="too_many_files", path=subpath or ".",
                                      detail=f"{dropped} relevant file(s) not fetched (limit {max_files} files / {limits.max_total_bytes} bytes)"))
    return plan
