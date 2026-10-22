import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { createMutationPolicy, requireConfirmation, type MutationPolicy } from "../guards.js";
import { ToolRegistry } from "../tool-registry.js";
import { trustedText } from "../untrusted.js";

const SIGHTING_TYPE_LABELS = ["Sighting", "False positive", "Expiration"];
const SIGHTINGS_DEFAULT_LIMIT = 100;
const SIGHTINGS_MAX_LIMIT = 500;

const missingSightingTarget = (params: { attributeId?: unknown; value?: unknown }): string | undefined =>
  !params.attributeId && !params.value ? "Either attributeId or value must be provided." : undefined;

export function registerSightingTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  tools.add(
    "misp_list_sightings",
    `List the sightings recorded on an event: who saw which attribute, when, and whether it was a sighting, a false positive, or an expiration. Returns at most limit sightings (default ${SIGHTINGS_DEFAULT_LIMIT}, max ${SIGHTINGS_MAX_LIMIT}) because the endpoint returns the full list; the result says when it was truncated.`,
    {
      eventId: z.string().describe("Numeric event ID to list sightings for (UUIDs are not accepted by this endpoint)"),
      limit: z.number().int().min(1).max(SIGHTINGS_MAX_LIMIT).optional()
        .describe(`Max sightings to return (default ${SIGHTINGS_DEFAULT_LIMIT}, max ${SIGHTINGS_MAX_LIMIT})`),
    },
    async ({ eventId, limit }) => {
      try {
        const all = await client.listSightings(eventId);

        if (all.length === 0) {
          return {
            content: [{ type: "text", text: `No sightings found for event ${eventId}.` }],
          };
        }

        const cap = limit ?? SIGHTINGS_DEFAULT_LIMIT;
        const shown = all.slice(0, cap);
        const summary = shown.map((s) => ({
          id: s.id,
          attribute_id: s.attribute_id,
          event_id: s.event_id,
          type: SIGHTING_TYPE_LABELS[parseInt(s.type, 10)] ?? `Unknown (${s.type})`,
          source: s.source || undefined,
          date_sighting: s.date_sighting,
          organisation: s.Organisation?.name || undefined,
        }));

        return {
          content: [
            { type: "text", text: JSON.stringify(summary, null, 2) },
            ...(all.length > shown.length
              ? [trustedText(`Note: showing the first ${shown.length} of ${all.length} sightings. Raise limit (max ${SIGHTINGS_MAX_LIMIT}) to see more.`)]
              : []),
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error listing sightings: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

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
        const missing = missingSightingTarget(params);
        if (missing) {
          return { content: [{ type: "text", text: missing }], isError: true };
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

        const typeLabels = SIGHTING_TYPE_LABELS;

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
    },
    missingSightingTarget
  );
}
