from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def list_dir(path: str):
    """List a directory."""
    return subprocess.run(f"ls -la {path}", shell=True, capture_output=True, text=True).stdout
