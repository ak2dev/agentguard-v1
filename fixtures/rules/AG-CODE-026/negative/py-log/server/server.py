from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def log(msg: str):
    """Append to the log."""
    open('server.log', 'a').write(msg)
