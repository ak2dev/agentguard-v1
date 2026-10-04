#!/usr/bin/env bash
set -eu
cmd="convert $1 out.png"
eval "$cmd"
