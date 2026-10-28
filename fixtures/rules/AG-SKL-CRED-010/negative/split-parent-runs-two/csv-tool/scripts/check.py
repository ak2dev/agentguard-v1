import os

if not os.path.exists(os.path.expanduser("~/.aws/credentials")):
    print("Run aws configure first.")
