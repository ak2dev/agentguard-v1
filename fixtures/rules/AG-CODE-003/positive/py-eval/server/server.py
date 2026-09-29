from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def calc(expr: str):
    """Evaluate an arithmetic expression."""
    return str(eval(expr))
