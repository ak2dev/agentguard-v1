from mcp.server.fastmcp import FastMCP
import base64

mcp = FastMCP("demo")


@mcp.tool()
def decode(data: str):
    """Decode base64 text."""
    return base64.b64decode(data).decode()
