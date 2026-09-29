"""Hardened YAML loading.

* Only core-schema types (SafeLoader); custom and python tags are rejected.
* Anchors and aliases are rejected outright (no billion-laughs, and skills
  have no legitimate use for them).
* Duplicate mapping keys are recorded (later-wins is how most loaders behave,
  which lets an attacker hide a value from a human reviewer).
* Node count and nesting depth are bounded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, SequenceNode


class YamlRejected(ValueError):
    pass


@dataclass
class YamlResult:
    value: Any = None
    duplicate_keys: list[tuple[str, int]] = field(default_factory=list)  # (key, line)
    error: str | None = None
    anchors_used: bool = False


def _make_loader(max_nodes: int, max_depth: int, dups: list[tuple[str, int]]):
    class _Loader(yaml.SafeLoader):
        _nodes = 0

        def compose_node(self, parent: Node | None, index: Any) -> Node:  # type: ignore[override]
            if self.check_event(AliasEvent):
                raise YamlRejected("YAML aliases are not allowed")
            event = self.peek_event()
            if getattr(event, "anchor", None):
                raise YamlRejected("YAML anchors are not allowed")
            _Loader._nodes += 1
            if _Loader._nodes > max_nodes:
                raise YamlRejected("YAML document exceeds node limit")
            depth = getattr(self, "_depth", 0)
            if depth > max_depth:
                raise YamlRejected("YAML document exceeds depth limit")
            self._depth = depth + 1
            try:
                return super().compose_node(parent, index)
            finally:
                self._depth = depth

        def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict:  # type: ignore[override]
            seen: set[Any] = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=True)
                try:
                    hashable = key in seen
                except TypeError:
                    raise YamlRejected("unhashable mapping key") from None
                if hashable:
                    dups.append((str(key), key_node.start_mark.line + 1))
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    _Loader._nodes = 0
    return _Loader


def safe_load(text: str, *, max_nodes: int = 50_000, max_depth: int = 64) -> YamlResult:
    result = YamlResult()
    loader_cls = _make_loader(max_nodes, max_depth, result.duplicate_keys)
    loader = None
    try:
        loader = loader_cls(text)
        result.value = loader.get_single_data()
    except YamlRejected as exc:
        result.error = str(exc)
        result.anchors_used = "alias" in str(exc) or "anchor" in str(exc)
    except yaml.YAMLError as exc:
        result.error = f"YAML error: {str(exc).splitlines()[0][:200]}"
    except (RecursionError, ValueError, TypeError) as exc:
        result.error = f"YAML error: {type(exc).__name__}"
    finally:
        if loader is not None:
            loader.dispose()
    return result
