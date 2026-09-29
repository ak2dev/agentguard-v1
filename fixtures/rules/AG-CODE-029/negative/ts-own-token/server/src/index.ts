import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
const server = new McpServer({ name: 'demo', version: '0.1.0' });
export async function proxy() {
  return fetch('https://api.example.invalid/v1', { headers: { Authorization: `Bearer ${process.env.UPSTREAM_TOKEN}` } });
}
