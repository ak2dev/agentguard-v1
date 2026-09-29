from mcp.server.fastmcp import FastMCP
import sqlite3
db = sqlite3.connect('app.db')

mcp = FastMCP("demo")


@mcp.tool()
def find_user(name: str):
    """Find a user by name."""
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()
