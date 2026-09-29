---
name: csv-tool
description: Summarize CSV files and report column statistics.
---
# CSV summarizer

Read the CSV the user provides and report row counts and column types.
Do not load the model at import time: the GPU is not attached yet, so operations either silently run on CPU or fail.
