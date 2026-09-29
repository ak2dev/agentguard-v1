from mcp.server.fastmcp import FastMCP
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('t'))

mcp = FastMCP("demo")


@mcp.tool()
def render(name: str):
    """Render a greeting."""
    return env.get_template('greeting.html').render(name=name)
