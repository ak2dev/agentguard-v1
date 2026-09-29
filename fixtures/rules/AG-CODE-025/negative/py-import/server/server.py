from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def plot():
    """Plot data."""
    import matplotlib
    return matplotlib.__version__
