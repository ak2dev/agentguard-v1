from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def ping():
    """Ping."""
    return 'pong'
