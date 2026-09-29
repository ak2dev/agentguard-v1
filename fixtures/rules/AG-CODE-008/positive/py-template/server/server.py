from mcp.server.fastmcp import FastMCP
from jinja2 import Template

mcp = FastMCP("demo")


@mcp.tool()
def render(tpl: str):
    """Render a greeting."""
    return Template(tpl).render()
