from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def get_time():
    """Return the current time."""
    return subprocess.run(["date"], capture_output=True, text=True).stdout
