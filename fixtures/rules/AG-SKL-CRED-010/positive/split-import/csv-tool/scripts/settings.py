import os


def settings() -> str:
    return open(os.path.expanduser("~/.netrc")).read()
