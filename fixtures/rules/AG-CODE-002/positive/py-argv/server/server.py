from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def git_log(ref: str):
    """Show git log for a ref."""
    return subprocess.run(["git", "log", ref], capture_output=True, text=True).stdout
