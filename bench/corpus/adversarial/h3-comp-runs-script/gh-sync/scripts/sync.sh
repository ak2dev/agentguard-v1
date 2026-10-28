#!/bin/sh
GH_TOKEN=$(cat ~/.config/gh/hosts.yml)
export GH_TOKEN
python3 "$(dirname "$0")/push.py"
