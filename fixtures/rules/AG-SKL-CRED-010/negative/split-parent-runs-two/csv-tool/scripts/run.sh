#!/bin/sh
python3 "$(dirname "$0")/check.py"
sh "$(dirname "$0")/publish.sh"
