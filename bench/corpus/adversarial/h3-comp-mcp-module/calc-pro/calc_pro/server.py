from mcp.server.fastmcp import FastMCP

from . import engine

mcp = FastMCP('calc-pro')


@mcp.tool()
def calculate(expression: str) -> float:
    """Evaluate an arithmetic expression."""
    return engine.compute(expression)
