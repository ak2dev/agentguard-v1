"""Select what to judge, call the provider within a budget, validate, cache.

Results are cached on disk by (prompt version, provider, model, kind,
content hash), so repeated scans of unchanged content cost nothing and are
stable. The judge is excluded from the determinism guarantee; cached results
make it repeatable in practice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ..core.inventory import build_inventory
from ..core.judge_models import JUDGE_PROMPT_VERSION, VERDICT_MODELS, JudgeKind, JudgeResult, verdict_schema
from ..core.models import LoadLimits
from ..core.models.enums import ArtifactRole, ComponentKind
from ..core.textutil import sha256_hex
from ..core.tree import ArtifactTree
from ..io.intel_store import data_home
from .prompt import build_prompt, strict_schema
from .providers import JudgeError, Provider


@dataclass
class Item:
    kind: JudgeKind
    component_id: str
    path: str
    sections: list[tuple[str, str]]

    @property
    def content_hash(self) -> str:
        return sha256_hex("\n\x00".join(f"{label}\x00{text}" for label, text in self.sections))


def select_items(tree: ArtifactTree, limits: LoadLimits | None = None) -> list[Item]:
    inv = build_inventory(tree, limits or LoadLimits())
    items: list[Item] = []
    by_comp: dict[str, list] = {}
    for at in inv.texts.values():
        by_comp.setdefault(at.artifact.component_id, []).append(at)
    for comp in sorted(inv.components.values(), key=lambda c: c.id):
        texts = sorted(by_comp.get(comp.id, []), key=lambda t: t.path)
        md = [t for t in texts if t.artifact.role in (ArtifactRole.skill_md, ArtifactRole.instruction_md)]
        code = [t for t in texts if t.artifact.role in (ArtifactRole.script, ArtifactRole.source_code)]
        for t in md:
            items.append(Item("manipulation", comp.id, t.path, [(t.path, t.text)]))
        if comp.tools:
            desc = "\n".join(f"tool {tl.name}: {tl.description or ''} {json.dumps(tl.input_schema)[:2000]}" for tl in comp.tools)
            items.append(Item("manipulation", comp.id, comp.tools[0].span.path if comp.tools[0].span else comp.root,
                              [(f"{comp.name} tool definitions", desc)]))
        if code and comp.kind in (ComponentKind.skill, ComponentKind.mcp_server):
            declared = "\n".join(t.text for t in md) if md else "\n".join(
                f"tool {tl.name}: {tl.description or ''}" for tl in comp.tools)
            items.append(Item("mismatch", comp.id, code[0].path,
                              [("declared description", declared)] + [(t.path, t.text) for t in code]))
    return items


def _cache_path(provider: Provider, item: Item) -> Path:
    key = sha256_hex(f"{JUDGE_PROMPT_VERSION}|{provider.name}|{provider.model}|{item.kind}|{item.content_hash}")
    return data_home() / "judge-cache" / f"{key}.json"


def run_judge(tree: ArtifactTree, provider: Provider, *, budget_calls: int = 20,
              limits: LoadLimits | None = None, use_cache: bool = True) -> list[JudgeResult]:
    results: list[JudgeResult] = []
    calls = 0
    for item in select_items(tree, limits):
        base = dict(kind=item.kind, component_id=item.component_id, path=item.path, content_hash=item.content_hash,
                    provider=provider.name, model=provider.model)
        cache = _cache_path(provider, item)
        if use_cache and cache.is_file():
            try:
                results.append(JudgeResult.model_validate_json(cache.read_text(encoding="utf-8")).model_copy(update={"cached": True}))
                continue
            except ValidationError:
                pass
        if calls >= budget_calls:
            results.append(JudgeResult(**base, error="judge budget exhausted (--llm-budget)"))
            continue
        system, user, truncated = build_prompt(item.kind, item.sections)
        calls += 1
        try:
            text = provider.complete(system, user, strict_schema(verdict_schema(item.kind)))
            verdict = VERDICT_MODELS[item.kind].model_validate_json(text)
        except JudgeError as exc:
            results.append(JudgeResult(**base, truncated=truncated, error=str(exc)[:200]))
            continue
        except (ValidationError, ValueError):
            # Anything that does not validate against the schema is discarded, never interpreted.
            results.append(JudgeResult(**base, truncated=truncated, error="verdict failed schema validation; discarded"))
            continue
        result = JudgeResult(**base, truncated=truncated, verdict=verdict)
        if use_cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(result.model_dump_json(), encoding="utf-8")
        results.append(result)
    return results
