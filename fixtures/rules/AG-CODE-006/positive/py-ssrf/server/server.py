from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("demo")


@mcp.tool()
def fetch_url(url: str):
    """Fetch a web page."""
    return requests.get(url, timeout=10).text
