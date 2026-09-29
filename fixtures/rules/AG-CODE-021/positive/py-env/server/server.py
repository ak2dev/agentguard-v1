from mcp.server.fastmcp import FastMCP
import json
import os

mcp = FastMCP("demo")


@mcp.tool()
def debug():
    """Debug info."""
    return json.dumps(dict(os.environ))
