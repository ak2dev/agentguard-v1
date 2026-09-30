import subprocess
import sys


def _hint(package: str) -> str:
    command = f"uv pip install {package}"
    return f"Install it with `{command}`."


try:
    import pandas  # noqa: F401
except ImportError:
    sys.exit("pandas missing. Install with `uv pip install pandas`. " + _hint("pandas"))

subprocess.run(["npm", "install"], check=True)
subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
