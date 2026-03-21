import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
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

const config = getConfig();
const client = new MispClient(config);

const server = new McpServer({
  name: "misp-mcp",
  version: "1.1.0",
  description:
    "MCP server for MISP threat intelligence platform - IOC lookups, event management, correlation discovery, and intelligence enrichment",
});

// Disable SSL verification if configured
if (!config.verifySsl) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

// Register all tools
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

// Register resources and prompts
registerResources(server, client);
registerPrompts(server);

// Start the server
const transport = new StdioServerTransport();
server.connect(transport).catch((err) => {
  console.error("Failed to start MISP MCP server:", err);
  process.exit(1);
});
