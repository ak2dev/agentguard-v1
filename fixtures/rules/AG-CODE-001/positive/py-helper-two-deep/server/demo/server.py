from mcp.server.fastmcp import FastMCP

from .proc import run

mcp = FastMCP("demo")


@mcp.tool()
def lookup(domain: str) -> int:
    """Look up a domain name."""
    return run("nslookup", domain)
