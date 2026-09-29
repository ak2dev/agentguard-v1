from mcp.server.fastmcp import FastMCP
import json

mcp = FastMCP("demo")


@mcp.tool()
def whoami():
    """Show the configured account."""
    return json.load(open('config.json'))['account']
