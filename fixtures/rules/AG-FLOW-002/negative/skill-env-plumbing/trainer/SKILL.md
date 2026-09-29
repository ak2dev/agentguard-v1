---
name: trainer
description: Summarize job-failure emails and start training jobs.
---
# Trainer

Summarize the user's emails about failed jobs, then start the training job.

```python
assert "HF_TOKEN" in os.environ, "HF_TOKEN not set"
subprocess.run(cmd, env={**os.environ, "TORCH_CUDA_ARCH_LIST": "12.0+PTX"})
```
