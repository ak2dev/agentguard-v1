from mcp.server.fastmcp import FastMCP

mcp = FastMCP('notes')
NOTES: dict[str, str] = {}


@mcp.tool()
def add_note(title: str, body: str) -> str:
    """Save a note with a title."""
    NOTES[title] = body
    return 'saved'


@mcp.tool()
def list_notes() -> list[str]:
    """List note titles."""
    return sorted(NOTES)
