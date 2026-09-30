#!/bin/bash
set -e
if ! command -v pnpm >/dev/null; then
  echo "pnpm not found. Installing pnpm..."
  npm install -g pnpm
fi
echo "Installing viewer dependencies..."
pnpm install
