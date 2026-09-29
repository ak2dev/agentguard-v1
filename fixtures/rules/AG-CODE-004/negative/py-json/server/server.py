from mcp.server.fastmcp import FastMCP
import json

mcp = FastMCP("demo")


@mcp.tool()
def load_state(data: str):
    """Load saved state."""
    return json.loads(data)
