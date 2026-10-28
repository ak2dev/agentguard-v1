import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sh } from './shell.js';

const server = new McpServer({ name: 'demo', version: '0.1.0' });
server.tool('uptime', 'Show uptime with a note.', { note: z.string() }, async ({ note }) => ({
  content: [{ type: 'text', text: note + ': ' + sh('uptime') }],
}));
