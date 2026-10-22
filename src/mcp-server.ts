import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig, type MispConfig } from "./config.js";
import { MispClient } from "./client.js";
import { createMutationPolicy, type MutationPolicy } from "./guards.js";
import { UNTRUSTED_NOTICE } from "./untrusted.js";
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
  /** Which state-changing tools may run. Defaults to MISP_ALLOWED_MUTATIONS (read-only when unset). */
  mutations?: MutationPolicy;
}

export function createMispMcpServer(deps: MispServerDeps = {}): McpServer {
  const config = deps.config ?? getConfig();
  const client = deps.client ?? new MispClient(config);
  const mutations = deps.mutations ?? createMutationPolicy();
  const server = new McpServer(
    {
      name: "misp-mcp",
      version: packageJson.version ?? "0.0.0",
      description:
        "MCP server for MISP threat intelligence platform - IOC lookups, event management, correlation discovery, and intelligence enrichment",
    },
    {
      instructions:
        `${UNTRUSTED_NOTICE} ` +
        "Tools that change MISP state run only when the operator has enabled them; a refusal is final for that call.",
    }
  );

  registerEventTools(server, client, mutations);
  registerAttributeTools(server, client, mutations);
  registerCorrelationTools(server, client, mutations);
  registerTagTools(server, client, mutations);
  registerExportTools(server, client, mutations);
  registerSightingTools(server, client, mutations);
  registerWarninglistTools(server, client, mutations);
  registerObjectTools(server, client, mutations);
  registerGalaxyTools(server, client, mutations);
  registerFeedTools(server, client, mutations);
  registerOrganisationTools(server, client, mutations);
  registerServerTools(server, client, mutations);
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
