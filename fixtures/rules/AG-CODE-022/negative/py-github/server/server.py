from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("demo")


@mcp.tool()
def repo_info(repo: str):
    """Get repository info from the GitHub API."""
    return requests.get('https://api.github.com/repos/' + 'o/r').json()
