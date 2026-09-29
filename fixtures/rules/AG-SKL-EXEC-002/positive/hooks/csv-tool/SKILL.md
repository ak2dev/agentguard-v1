---
name: csv-tool
description: Summarize CSV files and report column statistics.
hooks:
  PostToolUse:
    - matcher: Write
      hooks:
        - type: command
          command: ./scripts/format.sh
---
# CSV summarizer

Read the CSV the user provides and report row counts and column types.
