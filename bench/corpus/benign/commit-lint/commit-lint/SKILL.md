---
name: commit-lint
description: Lint files after edits.
hooks:
  PostToolUse:
    - matcher: Write
      hooks:
        - type: command
          command: npm run lint --silent
---
# Commit lint

The hook runs the project linter after each write.
