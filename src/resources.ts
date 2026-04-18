import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MispClient } from "./client.js";

export function registerResources(server: McpServer, client: MispClient): void {
  // Attribute types and categories
  server.resource(
    "types",
    "misp://types",
    {
      description: "All supported MISP attribute types and categories with their mappings",
      mimeType: "application/json",
    },
    async () => {
      const types = await client.describeTypes();

      const summary = {
        types: types.types,
        categories: types.categories,
        category_type_mappings: types.category_type_mappings,
        type_defaults: Object.entries(types.sane_defaults).map(([type, info]) => ({
          type,
          default_category: info.default_category,
          to_ids: info.to_ids === 1,
        })),
      };

      return {
        contents: [
          {
            uri: "misp://types",
            mimeType: "application/json",
            text: JSON.stringify(summary, null, 2),
          },
        ],
      };
    }
  );

  // Instance capabilities (types + categories supported by this MISP)
  server.resource(
    "statistics",
    "misp://statistics",
    {
      description: "MISP instance capability summary (supported attribute types and categories). Use misp_search_events for actual counts.",
      mimeType: "application/json",
    },
    async () => {
      const types = await client.describeTypes();

      const stats = {
        available_types: types.types.length,
        available_categories: types.categories.length,
        note: "This resource reports capability metadata, not event totals. Use misp_search_events with date/tag filters to count events.",
      };

      return {
        contents: [
          {
            uri: "misp://statistics",
            mimeType: "application/json",
            text: JSON.stringify(stats, null, 2),
          },
        ],
      };
    }
  );

  // Available taxonomies
  server.resource(
    "taxonomies",
    "misp://taxonomies",
    {
      description: "Available MISP taxonomies (TLP, MITRE ATT&CK, etc.)",
      mimeType: "application/json",
    },
    async () => {
      const taxonomies = await client.listTaxonomies();

      const summary = taxonomies.map((t) => ({
        namespace: t.namespace,
        description: t.description,
        version: t.version,
        enabled: t.enabled,
      }));

      return {
        contents: [
          {
            uri: "misp://taxonomies",
            mimeType: "application/json",
            text: JSON.stringify(summary, null, 2),
          },
        ],
      };
    }
  );
}
