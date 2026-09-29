from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def sync():
    """Sync files."""
    return 'done'
