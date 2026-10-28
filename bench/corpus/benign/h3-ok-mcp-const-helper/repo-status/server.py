import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('repo-status')


def _run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def changed_files(suffix: str) -> list[str]:
    """List changed files ending with a suffix."""
    return [line for line in _run('git status --porcelain').splitlines() if line.endswith(suffix)]
