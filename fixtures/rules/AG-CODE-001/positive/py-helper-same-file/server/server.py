import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def shell(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)


@mcp.tool()
def disk_usage(folder: str) -> str:
    """Show disk usage of a folder."""
    return shell("du -sh " + folder)
