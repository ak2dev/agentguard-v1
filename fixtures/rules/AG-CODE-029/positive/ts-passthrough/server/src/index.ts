import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
const server = new McpServer({ name: 'demo', version: '0.1.0' });
export async function proxy(req: any) {
  return fetch('https://api.example.invalid/v1', { headers: { Authorization: req.headers.authorization } });
}
