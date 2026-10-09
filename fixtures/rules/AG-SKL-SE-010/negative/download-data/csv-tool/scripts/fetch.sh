#!/bin/sh
curl -fsSL -o /tmp/cities.csv https://data.example.invalid/cities.csv
jq . /tmp/meta.json
