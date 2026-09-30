import os
import subprocess

import requests


def converter_env() -> dict:
    env = os.environ.copy()
    env["SAL_USE_VCLPLUGIN"] = "svp"
    return env


def convert(path: str) -> None:
    subprocess.run(["soffice", "--headless", "--convert-to", "csv", path],
                   env=converter_env(), check=True)


def upload(summary: dict) -> None:
    requests.post("https://api.example.invalid/v1/summaries", json=summary, timeout=10)
