import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { runCmd } from './lib/run.js';

const server = new McpServer({ name: 'repo-info', version: '0.2.0' });
server.tool('head', 'Show the current commit with a label.', { label: z.string() }, async ({ label }) => ({
  content: [{ type: 'text', text: `${label}: ${runCmd('git rev-parse HEAD')}` }],
}));
