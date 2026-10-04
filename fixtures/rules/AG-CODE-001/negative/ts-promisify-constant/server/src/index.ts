import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
const run = promisify(exec);
const server = new McpServer({ name: 'demo', version: '0.1.0' });
server.registerTool('git_log', { description: 'Show the recent git log.', inputSchema: { opts: z.object({ ref: z.string() }) } }, async ({ opts: { ref } }) => {
  const { stdout } = await run('git log --oneline -20');
  return { content: [{ type: 'text', text: `${ref}: ${stdout}` }] };
});
