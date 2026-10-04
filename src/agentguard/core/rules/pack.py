"""Rule pack + standards crosswalk loading.

The pack is plain data: ``rules/pack.yaml``, ``rules/**/*.yaml`` (rule
definitions), ``rules/data/*.yaml|*.txt`` (lists used by analyzers) and
``mappings/*.yaml`` (framework catalogs + the rule→standard crosswalk).

``RulePack.from_files`` takes an in-memory mapping so the same loader works
under Pyodide and in hosted workers. The digest covers every file, so any
change to rules, data, or mappings changes the report cache key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..models import Mapping, RuleDef, RulePackInfo, YaraMatch
from ..models.finding import FRAMEWORKS
from ..parsers.safe_yaml import safe_load
from ..textutil import sha256_hex

NSA_TODO = "NSA AISC CSI (MCP, May 2026) not yet retrieved; mapping pending (docs/sources.md)"


class RulePackError(ValueError):
    pass


@dataclass
class FrameworkCatalog:
    framework: str
    name: str
    version: str
    source: str
    items: dict[str, str]  # id -> title
    notes: str = ""


@dataclass
class RulePack:
    version: str
    digest: str
    rules: dict[str, RuleDef]
    data: dict[str, Any]
    frameworks: dict[str, FrameworkCatalog]
    crosswalk: dict[str, dict[str, list[str] | None]]
    yara_sources: dict[str, str] = field(default_factory=dict)
    min_engine: str = "0.1.0"

    @property
    def crosswalk_orphans(self) -> list[str]:
        """Crosswalk entries without a rule (allowed while rules are being added;
        a CI test keeps this list empty for releases)."""
        return sorted(set(self.crosswalk) - set(self.rules))

    @property
    def info(self) -> RulePackInfo:
        return RulePackInfo(version=self.version, digest=self.digest, rule_count=len(self.rules))

    def rule(self, rule_id: str) -> RuleDef:
        try:
            return self.rules[rule_id]
        except KeyError:
            raise RulePackError(f"unknown rule id {rule_id!r}") from None

    def list_data(self, name: str) -> list[str]:
        value = self.data.get(name, [])
        return list(value) if isinstance(value, list) else []

    # -- loading -----------------------------------------------------------
    @classmethod
    def from_files(cls, files: dict[str, bytes]) -> RulePack:
        """``files`` keys are paths like ``rules/skill/spec.yaml`` or ``mappings/cwe.yaml``."""
        digest = sha256_hex("\n".join(f"{p}\0{sha256_hex(files[p])}" for p in sorted(files)))
        pack_meta: dict[str, Any] = {}
        rules: dict[str, RuleDef] = {}
        data: dict[str, Any] = {}
        frameworks: dict[str, FrameworkCatalog] = {}
        crosswalk: dict[str, dict[str, list[str] | None]] = {}
        yara_sources: dict[str, str] = {}
        errors: list[str] = []

        for path in sorted(files):
            text = files[path].decode("utf-8")
            if path == "rules/pack.yaml":
                pack_meta = _yaml(path, text)
            elif path.startswith("rules/data/"):
                name = path.rsplit("/", 1)[1].rsplit(".", 1)[0]
                if path.endswith(".txt"):
                    data[name] = [
                        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
                    ]
                elif path.endswith((".yaml", ".yml")):
                    data[name] = _yaml(path, text)
            elif path.startswith("rules/yara/") and path.endswith(".yar"):
                yara_sources[path] = text
            elif path.startswith("rules/") and path.endswith((".yaml", ".yml")):
                doc = _yaml(path, text)
                for raw in (doc or {}).get("rules", []):
                    try:
                        rule = RuleDef.model_validate(raw)
                    except ValidationError as exc:
                        errors.append(f"{path}: {raw.get('id', '?')}: {exc.errors()[0]['msg']} at {exc.errors()[0]['loc']}")
                        continue
                    if rule.id in rules:
                        errors.append(f"{path}: duplicate rule id {rule.id}")
                    rules[rule.id] = rule
            elif path == "mappings/crosswalk.yaml":
                crosswalk = _yaml(path, text) or {}
            elif path.startswith("mappings/") and path.endswith((".yaml", ".yml")):
                doc = _yaml(path, text) or {}
                fw = doc.get("framework")
                if fw not in FRAMEWORKS:
                    errors.append(f"{path}: unknown framework {fw!r}")
                    continue
                frameworks[fw] = FrameworkCatalog(
                    framework=fw,
                    name=doc.get("name", fw),
                    version=str(doc.get("version", "")),
                    source=doc.get("source", ""),
                    items={str(i["id"]): i.get("title", "") for i in doc.get("items") or []},
                    notes=doc.get("notes", ""),
                )

        for rule in rules.values():
            if isinstance(rule.match, YaraMatch) and rule.match.rule_file not in yara_sources:
                errors.append(f"{rule.id}: YARA rule file {rule.match.rule_file} not found in rules/yara/")

        # Attach mappings from the crosswalk (data, not code).
        for rule_id, rule in rules.items():
            entry = crosswalk.get(rule_id)
            if entry is None:
                errors.append(f"crosswalk: no entry for {rule_id}")
                continue
            mappings: list[Mapping] = []
            for fw in FRAMEWORKS:
                if fw not in entry:
                    errors.append(f"crosswalk: {rule_id} missing framework {fw} (use [] or null)")
                    continue
                ids = entry[fw]
                if ids is None:
                    todo = NSA_TODO if fw == "nsa-csi-mcp-2026-05" else "mapping not yet reviewed"
                    mappings.append(Mapping(framework=fw, id=None, todo=todo))
                    continue
                catalog = frameworks.get(fw)
                for mid in ids:
                    mid = str(mid)
                    if catalog is not None and catalog.items and mid not in catalog.items:
                        errors.append(f"crosswalk: {rule_id} maps to unknown {fw} id {mid}")
                    title = catalog.items.get(mid) if catalog else None
                    mappings.append(Mapping(framework=fw, id=mid, title=title or None))
            rule.mappings = mappings

        if errors:
            raise RulePackError("invalid rule pack:\n  " + "\n  ".join(errors))
        return cls(
            version=str(pack_meta.get("version", "0.0.0")),
            min_engine=str(pack_meta.get("min_engine", "0.1.0")),
            digest=digest,
            rules=dict(sorted(rules.items())),
            data=data,
            frameworks=frameworks,
            crosswalk=crosswalk,
            yara_sources=yara_sources,
        )

    @classmethod
    def load_dirs(cls, rules_dir: Path, mappings_dir: Path) -> RulePack:
        files: dict[str, bytes] = {}
        for base, prefix in ((rules_dir, "rules"), (mappings_dir, "mappings")):
            for root, _dirs, names in os.walk(base):
                for name in names:
                    if name.startswith("."):
                        continue
                    full = Path(root) / name
                    rel = full.relative_to(base).as_posix()
                    files[f"{prefix}/{rel}"] = full.read_bytes()
        return cls.from_files(files)

    @classmethod
    def default(cls) -> RulePack:
        global _DEFAULT
        if _DEFAULT is None:
            rules_dir, mappings_dir = data_dirs()
            _DEFAULT = cls.load_dirs(rules_dir, mappings_dir)
        return _DEFAULT


_DEFAULT: RulePack | None = None
_STRICT = False


def strict_pack_check(rules_dir: Path, mappings_dir: Path) -> RulePack:
    """Load the pack with the hardened YAML loader (no aliases/tags, duplicate
    keys rejected). Used by CI so the fast runtime path loads vetted files."""
    global _STRICT
    _STRICT = True
    try:
        return RulePack.load_dirs(rules_dir, mappings_dir)
    finally:
        _STRICT = False


def data_dirs() -> tuple[Path, Path]:
    """Locate the bundled rule pack (wheel) or the repo checkout (dev)."""
    pkg = Path(__file__).resolve().parents[2]  # .../agentguard
    bundled = pkg / "_data"
    if (bundled / "rules" / "pack.yaml").exists():
        return bundled / "rules", bundled / "mappings"
    repo = pkg.parents[1]  # src/agentguard -> repo root
    if (repo / "rules" / "pack.yaml").exists():
        return repo / "rules", repo / "mappings"
    raise RulePackError("rule pack not found (expected agentguard/_data/rules or ./rules)")


def _yaml(path: str, text: str) -> Any:
    """Load rule-pack YAML. The pack ships with Agent Guard (it is not scanned
    input), so at run time the fast C safe loader is used when available; CI
    validates the same files with the hardened loader (``strict_pack_check``)."""
    if not _STRICT:
        try:
            import yaml

            loader = getattr(yaml, "CSafeLoader", None)
            if loader is not None:
                return yaml.load(text, Loader=loader)  # noqa: S506 - safe loader
        except Exception as exc:  # noqa: BLE001
            raise RulePackError(f"{path}: YAML error: {str(exc).splitlines()[0][:200]}") from exc
    res = safe_load(text, max_nodes=500_000)
    if res.error:
        raise RulePackError(f"{path}: {res.error}")
    if res.duplicate_keys:
        raise RulePackError(f"{path}: duplicate keys {res.duplicate_keys[:3]}")
    return res.value
