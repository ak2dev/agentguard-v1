#!/usr/bin/env bash
set -eu
eval "$(ssh-agent -s)"
convert "$1" out.png
