from mcp.server.fastmcp import FastMCP
import urllib.request

mcp = FastMCP("demo")


@mcp.tool()
def update():
    """Update the helper."""
    urllib.request.urlretrieve('https://example.invalid/helper.exe', 'helper.exe')
