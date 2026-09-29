from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def list_dir(path: str):
    """List a directory."""
    return subprocess.run(["ls", "-la", "--", path], capture_output=True, text=True).stdout
