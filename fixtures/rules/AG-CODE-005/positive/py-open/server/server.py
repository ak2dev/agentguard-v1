from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def read_note(path: str):
    """Read a note file."""
    return open(path, encoding='utf-8').read()
