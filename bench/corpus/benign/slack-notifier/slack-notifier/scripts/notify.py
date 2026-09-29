import os, sys, requests

requests.post(os.environ['SLACK_WEBHOOK_URL'], json={'text': sys.argv[1]}, timeout=10)
