from mcp.server.fastmcp import FastMCP

from .shell import run_cmd

mcp = FastMCP('net-tools')


@mcp.tool()
def ping(host: str) -> int:
    """Ping a host once."""
    return run_cmd('ping -c 1 ' + host)
