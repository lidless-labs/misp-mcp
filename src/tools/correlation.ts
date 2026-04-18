import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerCorrelationTools(server: McpServer, client: MispClient): void {
  // Correlate an observable value
  server.tool(
    "misp_correlate",
    "Find correlations for a specific observable value across all MISP events",
    {
      value: z.string().describe("Observable value to correlate (IP, domain, hash, etc.)"),
    },
    async ({ value }) => {
      try {
        const attributes = await client.searchAttributes({
          value,
          includeCorrelations: true,
        });

        if (attributes.length === 0) {
          return {
            content: [{ type: "text", text: `No results found for "${value}" in MISP.` }],
          };
        }

        // Aggregate by event
        const eventMap = new Map<
          string,
          { event_id: string; event_info: string; attributes: Array<{ id: string; type: string; category: string; value: string }> }
        >();

        for (const attr of attributes) {
          const eid = attr.event_id;
          if (!eventMap.has(eid)) {
            eventMap.set(eid, {
              event_id: eid,
              event_info: attr.Event?.info || "Unknown",
              attributes: [],
            });
          }
          eventMap.get(eid)!.attributes.push({
            id: attr.id,
            type: attr.type,
            category: attr.category,
            value: attr.value,
          });
        }

        // Collect related attributes (correlations)
        const correlations: Array<{ value: string; type: string; event_id: string }> = [];
        for (const attr of attributes) {
          if (attr.RelatedAttribute) {
            for (const rel of attr.RelatedAttribute) {
              correlations.push({
                value: rel.value,
                type: rel.type,
                event_id: rel.event_id,
              });
            }
          }
        }

        const result = {
          searched_value: value,
          found_in_events: Array.from(eventMap.values()),
          total_events: eventMap.size,
          total_attributes: attributes.length,
          correlations: correlations.length > 0 ? correlations : undefined,
        };

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error correlating value: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Get related events
  server.tool(
    "misp_get_related_events",
    "Get events related to a specific event through shared attributes and correlations",
    {
      eventId: z.string().describe("Event ID to find related events for"),
      maxAttributes: z.number().int().positive().optional()
        .describe("Max number of to_ids attributes to correlate across (default 20). Higher values hit the MISP API more."),
      perAttributeLimit: z.number().int().positive().optional()
        .describe("Max matches to fetch per attribute value (default 100)."),
    },
    async ({ eventId, maxAttributes, perAttributeLimit }) => {
      try {
        const attrCap = maxAttributes ?? 20;
        const matchLimit = perAttributeLimit ?? 100;
        const event = await client.getEvent(eventId);
        const eventAttributes = event.Attribute || [];

        if (eventAttributes.length === 0) {
          return {
            content: [{ type: "text", text: `Event ${eventId} has no attributes to correlate.` }],
          };
        }

        // Search for correlations across event attributes
        const relatedMap = new Map<
          string,
          { event_id: string; event_info: string; overlapping_iocs: string[]; correlation_count: number }
        >();

        // Use event's RelatedEvent data if available
        if (event.RelatedEvent && event.RelatedEvent.length > 0) {
          for (const rel of event.RelatedEvent) {
            relatedMap.set(rel.Event.id, {
              event_id: rel.Event.id,
              event_info: rel.Event.info,
              overlapping_iocs: [],
              correlation_count: 0,
            });
          }
        }

        // Search for attribute values across other events
        const toIdsAttrs = eventAttributes.filter((a) => a.to_ids);
        const truncatedAttributes = toIdsAttrs.length > attrCap;
        const valuesToSearch = toIdsAttrs.slice(0, attrCap).map((a) => a.value);
        let truncatedMatches = false;

        for (const value of valuesToSearch) {
          const matches = await client.searchAttributes({
            value,
            includeCorrelations: true,
            limit: matchLimit,
          });
          if (matches.length >= matchLimit) {
            truncatedMatches = true;
          }

          for (const match of matches) {
            if (match.event_id !== eventId) {
              if (!relatedMap.has(match.event_id)) {
                relatedMap.set(match.event_id, {
                  event_id: match.event_id,
                  event_info: match.Event?.info || "Unknown",
                  overlapping_iocs: [],
                  correlation_count: 0,
                });
              }
              const entry = relatedMap.get(match.event_id)!;
              if (!entry.overlapping_iocs.includes(value)) {
                entry.overlapping_iocs.push(value);
              }
              entry.correlation_count++;
            }
          }
        }

        const related = Array.from(relatedMap.values()).sort(
          (a, b) => b.correlation_count - a.correlation_count
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  event_id: eventId,
                  event_info: event.info,
                  related_events: related,
                  total_related: related.length,
                  truncated: truncatedAttributes || truncatedMatches,
                  truncation_reason: truncatedAttributes
                    ? `Only the first ${attrCap} of ${toIdsAttrs.length} to_ids attributes were correlated. Raise maxAttributes to scan more.`
                    : truncatedMatches
                    ? `At least one attribute hit the per-attribute match limit of ${matchLimit}. Raise perAttributeLimit to see more correlations.`
                    : undefined,
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
            { type: "text", text: `Error finding related events: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Describe types
  server.tool(
    "misp_describe_types",
    "Get all available MISP attribute types and categories with their mappings",
    {},
    async () => {
      try {
        const types = await client.describeTypes();
        return {
          content: [{ type: "text", text: JSON.stringify(types, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error getting types: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
