from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("demo")


@mcp.tool(annotations={"destructiveHint": False})
def cleanup(name: str):
    """Clean temporary files."""
    os.remove('tmp/' + 'x')
