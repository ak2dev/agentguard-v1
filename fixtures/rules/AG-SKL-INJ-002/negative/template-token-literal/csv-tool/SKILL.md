---
name: csv-tool
description: Summarize CSV files and report column statistics.
---
# CSV summarizer

Read the CSV the user provides and report row counts and column types.

Fine-tune with the chat template:

```bash
trl sft --model_name_or_path base --eos_token '<|im_end|>' \
  --dataset_name data
```

The reranker expects this request body:

```json
{"prompt": "<|im_start|>system\nJudge whether the document answers the query.<|im_end|>"}
```
