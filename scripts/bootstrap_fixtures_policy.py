"""Bootstrap fixtures for policy rules (provenance only)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "rules"


def desktop(servers: dict) -> str:
    return json.dumps({"mcpServers": servers}, indent=2)


UNPINNED = {"command": "npx", "args": ["-y", "@example/server-files"]}
PINNED = {"command": "npx", "args": ["-y", "@example/server-files@1.2.3"]}
ATTACKER = {"command": "npx", "args": ["-y", "@attacker-example/server-files@1.0.0"]}
DOCKER = {"command": "docker", "args": ["run", "--rm", "-i", "example/mcp@sha256:" + "0" * 63 + "1"]}

F = {
    "AG-POL-001": {
        "positive": {"deny": {"_case.yaml": "policy:\n  deny_servers: ['*@attacker-example/*']\n", "claude_desktop_config.json": desktop({"files": ATTACKER})}},
        "negative": {"allowed": {"_case.yaml": "policy:\n  deny_servers: ['*@attacker-example/*']\n", "claude_desktop_config.json": desktop({"files": PINNED})}},
    },
    "AG-POL-002": {
        "positive": {"not-listed": {"_case.yaml": "policy:\n  allow_servers: ['npx -y @example/*']\n", "claude_desktop_config.json": desktop({"box": DOCKER})}},
        "negative": {"listed": {"_case.yaml": "policy:\n  allow_servers: ['npx -y @example/*']\n", "claude_desktop_config.json": desktop({"files": PINNED})}},
    },
    "AG-POL-003": {
        "positive": {"unpinned": {"_case.yaml": "policy:\n  require_pinning: true\n", "claude_desktop_config.json": desktop({"files": UNPINNED})}},
        "negative": {"pinned": {"_case.yaml": "policy:\n  require_pinning: true\n", "claude_desktop_config.json": desktop({"files": PINNED})}},
    },
    "AG-POL-005": {
        "positive": {"expired": {"_case.yaml": "today: 2026-09-28\nsuppressions:\n  - rule_id: AG-MCP-CFG-004\n    reason: accepted for the prototype phase\n    expires: 2026-01-01\n",
                                 "claude_desktop_config.json": desktop({"files": UNPINNED})}},
        "negative": {"active": {"_case.yaml": "today: 2026-09-28\nsuppressions:\n  - rule_id: AG-MCP-CFG-004\n    reason: accepted for the prototype phase\n    expires: 2099-01-01\n",
                                "claude_desktop_config.json": desktop({"files": UNPINNED})}},
    },
    "AG-POL-006": {
        "positive": {"no-reason": {"_case.yaml": "suppressions:\n  - rule_id: AG-MCP-CFG-004\n    expires: 2099-01-01\n", "claude_desktop_config.json": desktop({"files": UNPINNED})}},
        "negative": {"valid": {"_case.yaml": "suppressions:\n  - rule_id: AG-MCP-CFG-004\n    reason: accepted for the prototype phase\n    expires: 2099-01-01\n",
                               "claude_desktop_config.json": desktop({"files": UNPINNED})}},
    },
    "AG-POL-010": {
        "positive": {"config-changed": {"_case.yaml": "changed_paths: ['.agentguard.yaml', 'claude_desktop_config.json']\n", "claude_desktop_config.json": desktop({"files": PINNED})}},
        "negative": {"readme-changed": {"_case.yaml": "changed_paths: ['README.md']\n", "claude_desktop_config.json": desktop({"files": PINNED})}},
    },
}


def main() -> None:
    for rule_id, sides in F.items():
        base = ROOT / rule_id
        if base.exists():
            shutil.rmtree(base)
        for side, cases in sides.items():
            for case, files in cases.items():
                for rel, content in files.items():
                    p = base / side / case / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(content.encode("utf-8"))
    print(f"wrote fixtures for {len(F)} rules")


if __name__ == "__main__":
    main()
