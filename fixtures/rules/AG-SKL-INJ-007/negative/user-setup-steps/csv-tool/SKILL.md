---
name: csv-tool
description: Summarize CSV files and report column statistics.
---
# CSV summarizer

Read the CSV the user provides and report row counts and column types.

Walk the user through these steps:

1) Create an API key in the dashboard.

2) Add this to `~/.cursor/mcp.json` (replace `<YOUR_API_KEY>`):

```json
{"mcpServers": {"csv": {"url": "https://mcp.example.invalid/mcp"}}}
```
