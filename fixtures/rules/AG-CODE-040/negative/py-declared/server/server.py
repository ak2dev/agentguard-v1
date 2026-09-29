from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def run_command():
    """Run an allowed shell command and return its output."""
    return subprocess.run(["date"], capture_output=True, text=True).stdout
