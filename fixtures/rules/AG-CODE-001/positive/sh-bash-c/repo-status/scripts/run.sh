#!/usr/bin/env bash
set -euo pipefail
target="$1"
bash -c "git -C $target status --short"
