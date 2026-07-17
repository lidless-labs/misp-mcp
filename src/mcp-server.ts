import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig, type MispConfig } from "./config.js";
import { MispClient } from "./client.js";
import { registerEventTools } from "./tools/events.js";
import { registerAttributeTools } from "./tools/attributes.js";
import { registerCorrelationTools } from "./tools/correlation.js";
import { registerTagTools } from "./tools/tags.js";
import { registerExportTools } from "./tools/exports.js";
import { registerSightingTools } from "./tools/sightings.js";
import { registerWarninglistTools } from "./tools/warninglists.js";
import { registerObjectTools } from "./tools/objects.js";
import { registerGalaxyTools } from "./tools/galaxies.js";
import { registerFeedTools } from "./tools/feeds.js";
import { registerOrganisationTools } from "./tools/organisations.js";
import { registerServerTools } from "./tools/servers.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { version?: string };

export interface MispServerDeps {
  config?: MispConfig;
  client?: MispClient;
}

export function createMispMcpServer(deps: MispServerDeps = {}): McpServer {
  const config = deps.config ?? getConfig();
  const client = deps.client ?? new MispClient(config);
  const server = new McpServer({
    name: "misp-mcp",
    version: packageJson.version ?? "0.0.0",
    description:
      "MCP server for MISP threat intelligence platform - IOC lookups, event management, correlation discovery, and intelligence enrichment",
  });

  registerEventTools(server, client);
  registerAttributeTools(server, client);
  registerCorrelationTools(server, client);
  registerTagTools(server, client);
  registerExportTools(server, client);
  registerSightingTools(server, client);
  registerWarninglistTools(server, client);
  registerObjectTools(server, client);
  registerGalaxyTools(server, client);
  registerFeedTools(server, client);
  registerOrganisationTools(server, client);
  registerServerTools(server, client);
  registerResources(server, client);
  registerPrompts(server);

  return server;
}

function stripSchemaFromToolList(transport: StdioServerTransport): void {
  const send = transport.send.bind(transport);
  (transport as unknown as { send: typeof transport.send }).send = (message) => {
    const tools = (message as { result?: { tools?: unknown } })?.result?.tools;
    if (Array.isArray(tools)) {
      for (const tool of tools) {
        if (tool?.inputSchema) delete tool.inputSchema.$schema;
        if (tool?.outputSchema) delete tool.outputSchema.$schema;
      }
    }
    return send(message);
  };
}

export async function serveMcp(): Promise<void> {
  const config = getConfig();
  const server = createMispMcpServer({ config });
  const transport = new StdioServerTransport();
  stripSchemaFromToolList(transport);
  await server.connect(transport);
}
