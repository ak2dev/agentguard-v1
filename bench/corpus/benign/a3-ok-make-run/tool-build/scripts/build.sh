#!/bin/sh
set -eu
make build
./bin/app --version
