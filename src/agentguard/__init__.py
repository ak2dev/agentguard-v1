"""Agent Guard: an offline-first security scanner for AI agent skills,
instruction files and MCP servers.

Library API (stable; also used by Agent Guard Web and the Pyodide build)::

    from agentguard import ArtifactTree, ScanOptions, scan
    report = scan(ArtifactTree.from_mapping({"my-skill/SKILL.md": text}), ScanOptions())

``scan`` never touches the filesystem or network; build the tree with
``ArtifactTree.from_mapping``, ``from_archive`` or ``agentguard.io.fs_loader.load_path``.
"""

from .core.archive import from_archive
from .core.engine import ENGINE_VERSION, scan
from .core.models import Finding, Report, ScanOptions
from .core.report.render import render_cyclonedx, render_json, render_markdown, render_sarif
from .core.rules.pack import RulePack
from .core.tree import ArtifactTree

__version__ = "0.1.0.dev0"

__all__ = [
    "ENGINE_VERSION", "ArtifactTree", "Finding", "Report", "RulePack", "ScanOptions", "__version__",
    "from_archive", "render_cyclonedx", "render_json", "render_markdown", "render_sarif", "scan",
]
