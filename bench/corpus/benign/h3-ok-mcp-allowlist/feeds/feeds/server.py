from mcp.server.fastmcp import FastMCP

from .net import fetch_json

mcp = FastMCP('feeds')


@mcp.tool()
def read_feed(url: str) -> dict:
    """Read a JSON feed from an approved host."""
    return fetch_json(url)
