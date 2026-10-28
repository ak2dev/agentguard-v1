import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('git-log')


def _git(args: list[str]) -> str:
    return subprocess.run(['git', *args], capture_output=True, text=True).stdout


@mcp.tool()
def file_history(path: str) -> str:
    """Show the commits that touched a file."""
    return _git(['log', '--oneline', '--', path])
