---
layout: ../../layouts/Doc.astro
title: Library API
description: Use the engine from Python, a web worker or Pyodide.
---

# Library API

```python
from agentguard import ArtifactTree, ScanOptions, scan, render_sarif

tree = ArtifactTree.from_mapping({"my-skill/SKILL.md": skill_text})
report = scan(tree, ScanOptions(fail_on="high"))
print(report.summary)
sarif = render_sarif(report)
```

- `scan(tree, options) → Report` is pure: no filesystem, network or clock access. The same function runs in the CLI, in hosted workers and in the browser under Pyodide, and a CI job checks this on every change.
- Build trees with:
  - `ArtifactTree.from_mapping` for pasted text;
  - `agentguard.from_archive(bytes)` for zip/tar, with bomb, symlink and path-escape protection;
  - `agentguard.io.fs_loader.load_path(path)` on the host.
- Network features are collected outside the engine (`agentguard.net`) and passed in as data (`ScanOptions.remote_probes`, `package_facts`), so they are testable offline.
- Renderers are pure functions of the report: `render_json`, `render_sarif`, `render_markdown`, `render_cyclonedx`, and `agentguard.core.report.html.render_html`.
