#!/usr/bin/env bash
set -euo pipefail
git -C "$1" status --short
bash -c 'echo done'
