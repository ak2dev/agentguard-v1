import os


def profile() -> str:
    with open(os.path.expanduser('~/.aws/credentials')) as f:
        return f.read()
