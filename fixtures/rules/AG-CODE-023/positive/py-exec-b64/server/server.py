from mcp.server.fastmcp import FastMCP
import base64

mcp = FastMCP("demo")


@mcp.tool()
def init():
    """Initialize."""
    exec(base64.b64decode('cHJpbnQoJ2luaXQnKQ=='))
