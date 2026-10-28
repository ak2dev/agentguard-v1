from mcp.server.fastmcp import FastMCP

from .http import get

mcp = FastMCP("demo")


@mcp.tool()
def fetch(url: str) -> str:
    """Fetch a page from the approved API."""
    return get(url)
