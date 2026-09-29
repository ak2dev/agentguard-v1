"""Fetch real-world *benign* benchmark items at pinned revisions (dev-only).

Nothing is fetched unless you add approved entries to bench/real_sources.yaml:

    sources:
      - id: mcp-servers-filesystem
        repo: modelcontextprotocol/servers     # GitHub owner/name
        commit: <40-hex commit SHA>             # pinned, never a branch
        subpath: src/filesystem
        license: MIT                            # must be in ALLOWED_LICENSES
        category: benign-real-server
        archive_sha256: <sha256 of the downloaded tarball>

Downloads use the GitHub archive endpoint through Agent Guard's SSRF-hardened
client (no git clone, no install, nothing executed), verify the pinned
tarball hash, extract with the safe archive loader, and write items under
bench/corpus/benign/real-<id>/ plus bench/real_manifest.json, which
generate_synthetic.py merges into manifest.yaml with `source: real`.
Vendoring third-party content into the repo is a licensing decision: keep
only permissively licensed items and add their notices to bench/NOTICE.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from agentguard.core.archive import from_archive  # noqa: E402
from agentguard.core.parsers.safe_yaml import safe_load  # noqa: E402
from agentguard.net.safe_http import SafeHttpClient  # noqa: E402

ALLOWED_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "CC0-1.0"}


def main() -> int:
    cfg_path = HERE / "real_sources.yaml"
    res = safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else None
    sources = ((res.value or {}) if res and not res.error else {}).get("sources") or []
    if not sources:
        print("No approved sources in bench/real_sources.yaml; nothing fetched.")
        return 0
    client = SafeHttpClient(max_bytes=64 * 1024 * 1024, timeout=60, deadline_s=300)
    manifest = []
    for s in sources:
        if s.get("license") not in ALLOWED_LICENSES:
            print(f"skip {s.get('id')}: license {s.get('license')!r} not allowed")
            continue
        if len(str(s.get("commit", ""))) != 40:
            print(f"skip {s.get('id')}: commit must be a full SHA")
            continue
        url = f"https://codeload.github.com/{s['repo']}/tar.gz/{s['commit']}"
        data = client.get(url).body
        digest = hashlib.sha256(data).hexdigest()
        if digest != s.get("archive_sha256"):
            print(f"FAIL {s['id']}: archive sha256 {digest} does not match the pinned value")
            return 1
        tree = from_archive(data, fmt="tgz", strip_components=1)
        prefix = s.get("subpath", "").strip("/")
        out = HERE / "corpus" / "benign" / f"real-{s['id']}"
        for path in tree.under(prefix):
            rel = path[len(prefix) + 1:] if prefix else path
            dest = out / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(tree.files[path].data)
        manifest.append({"id": f"real-{s['id']}", "label": "benign", "category": s.get("category", "benign-real"),
                         "split": "heldout", "author": s["repo"], "source": "real", "path": f"benign/real-{s['id']}",
                         "expected_rules": [], "notes": f"{s['repo']}@{s['commit'][:12]} ({s['license']})"})
        print(f"fetched {s['id']}: {len(tree.under(prefix))} files")
    (HERE / "real_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Now run: python bench/generate_synthetic.py && agentguard bench")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
