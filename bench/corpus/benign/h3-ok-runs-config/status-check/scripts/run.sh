#!/bin/sh
export STATUS_URL=https://status.example.invalid/api/v2/summary.json
python3 "$(dirname "$0")/fetch.py"
