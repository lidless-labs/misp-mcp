import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { createMutationPolicy, requireConfirmation, type MutationPolicy } from "../guards.js";
import { ToolRegistry } from "../tool-registry.js";

export function registerSightingTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  tools.add(
    "misp_add_sighting",
    "Report a sighting of an IOC (confirms it was observed in the wild, marks as false positive, or sets expiration). Types 1 (false positive) and 2 (expiration) change how the IOC is treated and require confirm:true (or MISP_ALLOW_DESTRUCTIVE=true).",
    {
      attributeId: z.string().optional().describe("Attribute ID to sight (use this or value)"),
      value: z.string().optional().describe("Attribute value to sight (use this or attributeId)"),
      type: z.union([z.literal(0), z.literal(1), z.literal(2)])
        .describe("0=Sighting (seen in the wild), 1=False positive, 2=Expiration"),
      source: z.string().optional().describe("Source of the sighting (e.g., organization name, sensor ID)"),
      timestamp: z.string().optional().describe("Timestamp of the sighting (Unix timestamp)"),
      confirm: z.boolean().optional().describe("Must be true for type 1 (false positive) or type 2 (expiration) unless MISP_ALLOW_DESTRUCTIVE=true. Ignored for type 0."),
    },
    async (params) => {
      try {
        if (!params.attributeId && !params.value) {
          return {
            content: [
              { type: "text", text: "Either attributeId or value must be provided." },
            ],
            isError: true,
          };
        }

        if (params.type !== 0) {
          const guard = requireConfirmation(
            params.confirm,
            `recording a ${params.type === 1 ? "false-positive" : "expiration"} sighting`
          );
          if (guard) return guard;
        }

        const sighting = await client.addSighting({
          attributeId: params.attributeId,
          value: params.value,
          type: params.type,
          source: params.source,
          timestamp: params.timestamp,
        });

        const typeLabels = ["Sighting", "False positive", "Expiration"];

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  id: sighting.id,
                  type: typeLabels[params.type],
                  attribute_id: sighting.attribute_id,
                  event_id: sighting.event_id,
                  source: sighting.source,
                  date_sighting: sighting.date_sighting,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error adding sighting: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
