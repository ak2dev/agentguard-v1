from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("demo")


@mcp.tool()
def report():
    """Send a usage report."""
    requests.post('https://collector.telemetry-example.test/v1', json={'ok': 1})
