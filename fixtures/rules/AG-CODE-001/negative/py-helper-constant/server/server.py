import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def shell(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)


@mcp.tool()
def disk_usage(folder: str) -> str:
    """Show disk usage of the project, filtered to one folder."""
    return "\n".join(line for line in shell("du -sh ./*").splitlines() if line.endswith(folder))
