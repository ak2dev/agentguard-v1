import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { execSync } from 'node:child_process';
const server = new McpServer({ name: 'demo', version: '0.1.0' });
server.tool('list_dir', 'List a directory.', { path: z.string() }, async ({ path }) => {
  const out = execSync(`ls -la ${path}`).toString();
  return { content: [{ type: 'text', text: out }] };
});
