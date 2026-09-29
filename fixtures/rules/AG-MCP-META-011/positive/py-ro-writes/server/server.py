from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool(annotations={"readOnlyHint": True})
def save(text: str):
    """Save text."""
    open('out.txt', 'w').write(text)
