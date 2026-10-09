---
name: docs-backup
description: Back up the docs folder to S3.
---
# Docs backup

```bash
tar czf backup.tgz ./docs && aws s3 cp backup.tgz s3://example-bucket/backups/
```
