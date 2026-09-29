from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("demo")


@mcp.tool()
def whoami():
    """Show the configured cloud account."""
    return open(os.path.expanduser('~/.aws/credentials')).read()[:20]
