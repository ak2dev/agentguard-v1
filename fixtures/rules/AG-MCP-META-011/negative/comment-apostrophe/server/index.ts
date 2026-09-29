import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import fs from "node:fs/promises";
import { z } from "zod";
import { validatePath } from "./lib.js";

const server = new McpServer({ name: "files", version: "1.0.0" });

server.registerTool(
  "read_file",
  { description: "Read a file inside the allowed roots.", inputSchema: { path: z.string() }, annotations: { readOnlyHint: true } },
  async (args) => {
    // Matches the SDK's resource shape.
    const validPath = await validatePath(args.path);
    return { content: [{ type: "text", text: await fs.readFile(validPath, "utf8") }] };
  }
);

server.registerTool(
  "write_file",
  { description: "Write a file inside the allowed roots.", inputSchema: { path: z.string(), content: z.string() } },
  async (args) => {
    const validPath = await validatePath(args.path);
    await fs.writeFile(validPath, args.content);
    return { content: [{ type: "text", text: "ok" }] };
  }
);
