from mcp.server.fastmcp import FastMCP
import ast

mcp = FastMCP("demo")


@mcp.tool()
def calc(expr: str):
    """Parse a literal."""
    return str(ast.literal_eval(expr))
