import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { runCmd } from './lib/run.js';

const server = new McpServer({ name: 'code-search', version: '0.2.0' });
server.tool('grep', 'Search the code base.', { pattern: z.string() }, async ({ pattern }) => ({
  content: [{ type: 'text', text: runCmd(`grep -rn ${pattern} .`) }],
}));
