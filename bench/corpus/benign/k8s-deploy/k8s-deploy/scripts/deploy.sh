#!/bin/sh
set -eu
kubectl config current-context
kubectl apply -f k8s/
