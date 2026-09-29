"""Fetch real-world *benign* benchmark items at pinned revisions (dev-only).

Nothing is fetched unless you add approved entries to bench/real_sources.yaml:

    sources:
      - id: mcp-servers-filesystem
        repo: modelcontextprotocol/servers     # GitHub owner/name
        commit: <40-hex commit SHA>             # pinned, never a branch
        subpath: src/filesystem                 # one benchmark item per entry
        license: MIT                            # SPDX id or "A OR B" / "A AND B"; every id in ALLOWED_LICENSES
        license_file: LICENSE                   # optional; checked for the license text (relative to
                                                # subpath, or to the repo root when it starts with "/")
        split: heldout                          # dev | heldout (default heldout); dev = used while tuning rules
        category: benign-real-server
        archive_sha256: <sha256 of the downloaded tarball>
        exclude: ["*.lock"]                     # optional globs (relative to subpath) not to vendor

Entries that share repo+commit share one download. Downloads use the GitHub
archive endpoint through Agent Guard's SSRF-hardened client (no git clone, no
install, nothing executed), verify the pinned tarball hash, extract with the
safe archive loader, and write items under bench/corpus/benign/real-<id>/ plus
bench/real_manifest.json, which generate_synthetic.py merges into
manifest.yaml with `source: real`.
Vendoring third-party content into the repo is a licensing decision: keep
only permissively licensed items and add their notices to bench/NOTICE.
Repositories that license per directory (e.g. anthropics/skills, where some
skills are proprietary) must name each directory's own license_file.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from agentguard.core.archive import from_archive  # noqa: E402
from agentguard.core.parsers.safe_yaml import safe_load  # noqa: E402
from agentguard.net.safe_http import SafeHttpClient  # noqa: E402

ALLOWED_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "CC0-1.0", "CC-BY-4.0"}
# Text that must appear in a license_file declared for that license.
LICENSE_MARKERS = {
    "MIT": "Permission is hereby granted, free of charge",
    "Apache-2.0": "Apache License",
    "BSD-2-Clause": "Redistribution and use in source and binary forms",
    "BSD-3-Clause": "Redistribution and use in source and binary forms",
    "ISC": "Permission to use, copy, modify, and/or distribute",
    "0BSD": "Permission to use, copy, modify, and/or distribute",
    "CC0-1.0": "CC0",
    "CC-BY-4.0": "CC-BY-4.0",
}
# Repo-level license and notice files, copied to bench/licenses/ for items whose
# license lives at the repository root rather than inside the vendored subpath.
ROOT_NOTICES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "NOTICE", "NOTICE.txt", "NOTICE.md", "THIRD_PARTY_NOTICES.md")


def license_ids(expr: str) -> list[str]:
    return [t for t in str(expr or "").replace("(", " ").replace(")", " ").split() if t not in ("OR", "AND")]


def main() -> int:
    cfg_path = HERE / "real_sources.yaml"
    res = safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else None
    sources = ((res.value or {}) if res and not res.error else {}).get("sources") or []
    if not sources:
        print("No approved sources in bench/real_sources.yaml; nothing fetched.")
        return 0
    client = SafeHttpClient(max_bytes=64 * 1024 * 1024, timeout=60, deadline_s=300)
    trees: dict[tuple[str, str], object] = {}
    manifest = []
    for s in sources:
        ids = license_ids(s.get("license"))
        if not ids or any(i not in ALLOWED_LICENSES for i in ids):
            print(f"skip {s.get('id')}: license {s.get('license')!r} not allowed")
            continue
        if len(str(s.get("commit", ""))) != 40:
            print(f"skip {s.get('id')}: commit must be a full SHA")
            continue
        key = (s["repo"], s["commit"])
        if key not in trees:
            url = f"https://codeload.github.com/{s['repo']}/tar.gz/{s['commit']}"
            data = client.get(url).body
            digest = hashlib.sha256(data).hexdigest()
            if digest != s.get("archive_sha256"):
                print(f"FAIL {s['id']}: archive sha256 {digest} does not match the pinned value")
                return 1
            trees[key] = from_archive(data, fmt="tgz", strip_components=1)
            for name in ROOT_NOTICES:
                if name in trees[key].files:
                    dest = HERE / "licenses" / f"{s['repo'].replace('/', '__')}__{name}"
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(trees[key].files[name].data)
        tree = trees[key]
        prefix = s.get("subpath", "").strip("/")
        lic_file = s.get("license_file")
        if lic_file:
            lic_path = lic_file.lstrip("/") if lic_file.startswith("/") else "/".join(p for p in (prefix, lic_file) if p)
            f = tree.files.get(lic_path)
            text = f.data.decode("utf-8", "replace") if f else ""
            if not any(LICENSE_MARKERS[i] in text for i in ids):
                print(f"FAIL {s['id']}: {lic_path} does not contain the {s['license']} license text")
                return 1
        excludes = s.get("exclude") or []
        out = HERE / "corpus" / "benign" / f"real-{s['id']}"
        shutil.rmtree(out, ignore_errors=True)
        n = 0
        for path in tree.under(prefix):
            rel = path[len(prefix) + 1:] if prefix else path
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel.rsplit("/", 1)[-1], g) for g in excludes):
                continue
            dest = out / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(tree.files[path].data)
            n += 1
        if n == 0:
            # e.g. the subpath is a symlink, which the safe loader does not follow
            print(f"FAIL {s['id']}: no files under {prefix!r}")
            return 1
        split = s.get("split", "heldout")
        if split not in ("dev", "heldout"):
            print(f"FAIL {s['id']}: split must be dev or heldout")
            return 1
        manifest.append({"id": f"real-{s['id']}", "label": "benign", "category": s.get("category", "benign-real"),
                         "split": split, "author": s["repo"], "source": "real", "path": f"benign/real-{s['id']}",
                         "expected_rules": [], "notes": f"{s['repo']}@{s['commit'][:12]}/{prefix} ({s['license']})"})
        print(f"fetched {s['id']}: {n} files")
    (HERE / "real_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Now run: python bench/generate_synthetic.py && agentguard bench")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
