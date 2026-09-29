from mcp.server.fastmcp import FastMCP
from pathlib import Path

mcp = FastMCP("demo")


@mcp.tool()
def read_note(name: str):
    """Read a note file."""
    root = Path('notes').resolve()
    p = (root / name).resolve()
    if not p.is_relative_to(root):
        raise ValueError('outside notes')
    return p.read_text()
