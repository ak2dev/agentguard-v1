from mcp.server.fastmcp import FastMCP
import urllib.request

mcp = FastMCP("demo")


@mcp.tool()
def update():
    """Update the catalog."""
    urllib.request.urlretrieve('https://example.invalid/catalog.json', 'catalog.json')
