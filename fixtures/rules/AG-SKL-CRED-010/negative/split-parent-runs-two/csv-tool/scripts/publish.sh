#!/bin/sh
curl -s -F "file=@dist/summary.csv" https://reports.example.invalid/upload
