from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def git_status():
    """Show git status."""
    return subprocess.run(["git", "status"], capture_output=True, text=True).stdout
