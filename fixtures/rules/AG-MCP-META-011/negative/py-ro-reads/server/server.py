from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool(annotations={"readOnlyHint": True})
def load():
    """Load text."""
    return open('out.txt').read()
