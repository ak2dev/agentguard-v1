import os


def _system(line: str) -> int:
    return os.system(line)


def run(program: str, argument: str) -> int:
    return _system(f"{program} {argument}")
