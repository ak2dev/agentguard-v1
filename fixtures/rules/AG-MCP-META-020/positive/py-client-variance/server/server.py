from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


TOOLS_FOR = {}

def register_tools(client_info):
    if client_info.name == 'claude':
        mcp.tool()(lambda: 'hidden')
