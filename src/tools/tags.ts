import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { createMutationPolicy, type MutationPolicy } from "../guards.js";
import { ToolRegistry } from "../tool-registry.js";

export function registerTagTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  // List tags
  tools.add(
    "misp_list_tags",
    "List available MISP tags with usage statistics",
    {
      search: z.string().optional().describe("Search filter for tag names"),
      limit: z.number().optional().describe("Max results to return"),
    },
    async ({ search, limit }) => {
      try {
        let tags = await client.listTags(search);

        if (limit && limit > 0) {
          tags = tags.slice(0, limit);
        }

        if (tags.length === 0) {
          return {
            content: [{ type: "text", text: "No tags found." }],
          };
        }

        const summary = tags.map((t) => ({
          id: t.id,
          name: t.name,
          colour: t.colour,
          event_count: t.event_count,
          attribute_count: t.attribute_count,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error listing tags: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Search by tag
  tools.add(
    "misp_search_by_tag",
    "Search MISP events or attributes by tag (MITRE ATT&CK, TLP, custom tags)",
    {
      tag: z.string().describe("Tag name to search for (e.g., tlp:white, mitre-attack:T1059)"),
      type: z.enum(["event", "attribute"]).optional().describe("Search events or attributes (default: event)"),
    },
    async ({ tag, type: searchType }) => {
      try {
        if (searchType === "attribute") {
          const attributes = await client.searchAttributes({ tags: [tag] });

          if (attributes.length === 0) {
            return {
              content: [{ type: "text", text: `No attributes found with tag "${tag}".` }],
            };
          }

          const summary = attributes.map((a) => ({
            id: a.id,
            event_id: a.event_id,
            type: a.type,
            value: a.value,
            category: a.category,
            event_info: a.Event?.info,
          }));

          return {
            content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
          };
        }

        // Default: search events
        const events = await client.searchEvents({ tags: [tag] });

        if (events.length === 0) {
          return {
            content: [{ type: "text", text: `No events found with tag "${tag}".` }],
          };
        }

        const summary = events.map((e) => ({
          id: e.id,
          info: e.info,
          date: e.date,
          threat_level: ["", "High", "Medium", "Low", "Undefined"][parseInt(e.threat_level_id) || 0],
          org: e.Orgc?.name || "Unknown",
          tags: (e.Tag || []).map((t) => t.name),
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error searching by tag: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
