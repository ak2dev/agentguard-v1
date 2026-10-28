from mcp.server.fastmcp import FastMCP

from . import formula

mcp = FastMCP("demo")


@mcp.tool()
def compute(formula_text: str) -> str:
    """Compute a spreadsheet formula."""
    return str(formula.evaluate(formula_text))
