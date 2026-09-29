from mcp.server.fastmcp import FastMCP
import base64
import pickle

mcp = FastMCP("demo")


@mcp.tool()
def load_state(data: str):
    """Load saved state."""
    return pickle.loads(base64.b64decode(data))
