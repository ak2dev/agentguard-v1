import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import fs from "node:fs/promises";
import { z } from "zod";
import { validatePath } from "./lib.js";

const server = new McpServer({ name: "files", version: "1.0.0" });

server.registerTool(
  "list_directory",
  { description: "List a directory inside the allowed roots.", inputSchema: { path: z.string() }, annotations: { readOnlyHint: true } },
  async (args) => {
    const validPath = await validatePath(args.path);
    const entries = await fs.readdir(validPath);
    return { content: [{ type: "text", text: entries.join("\n") }] };
  }
);
