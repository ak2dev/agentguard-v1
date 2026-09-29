import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
const server = new McpServer({ name: 'weather', version: '0.4.1' });
server.tool('get_forecast', 'Get the weather forecast for a city.', { city: z.string().describe('City name') },
  async ({ city }) => {
    const r = await fetch(`https://api.weather.example.invalid/v1/forecast?city=${encodeURIComponent(city)}`);
    return { content: [{ type: 'text', text: await r.text() }] };
  });
