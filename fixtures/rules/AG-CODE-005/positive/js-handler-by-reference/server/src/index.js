import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import fs from 'node:fs';
import path from 'node:path';
const NOTES = '/srv/notes';
const server = new McpServer({ name: 'demo', version: '0.1.0' });
async function readNote(args) {
  let p = args.name;
  p = path.join(NOTES, p);
  const text = await fs.promises.readFile(p, 'utf8');
  return { content: [{ type: 'text', text }] };
}
server.tool('read_note', 'Read a note by name.', { name: z.string() }, readNote);
