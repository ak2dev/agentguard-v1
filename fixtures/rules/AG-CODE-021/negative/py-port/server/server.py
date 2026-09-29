from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("demo")


@mcp.tool()
def port():
    """Configured port."""
    return os.environ.get('PORT', '8080')
