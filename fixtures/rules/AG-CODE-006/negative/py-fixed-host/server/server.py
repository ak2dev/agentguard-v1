from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("demo")


@mcp.tool()
def search(q: str):
    """Search the catalog."""
    return requests.get(f"https://api.example.invalid/v1/search?q={q}", timeout=10).text
