import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as shell from './shell.js';

const server = new McpServer({ name: 'demo', version: '0.1.0' });
server.tool('count_lines', 'Count lines in a file.', { file: z.string() }, async ({ file }) => ({
  content: [{ type: 'text', text: shell.sh('wc -l ' + file) }],
}));
