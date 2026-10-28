import os


def run_cmd(cmd: str) -> int:
    return os.system(cmd)
