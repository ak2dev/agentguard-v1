import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('doc-convert')


def _run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def convert(path: str, fmt: str) -> str:
    """Convert a document to another format."""
    return _run(f'pandoc {path} --to {fmt}')
