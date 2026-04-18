import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerEventTools(server: McpServer, client: MispClient): void {
  // Search events
  server.tool(
    "misp_search_events",
    "Search MISP events by IOC value, type, tags, date range, or organization",
    {
      value: z.string().optional().describe("IOC value to search across all attributes"),
      type: z.string().optional().describe("Attribute type filter (ip-src, ip-dst, domain, md5, sha256, url, email-src, etc.)"),
      category: z.string().optional().describe("Category filter (Network activity, Payload delivery, External analysis, etc.)"),
      tags: z.array(z.string()).optional().describe("Tag filters (e.g., tlp:white, misp-galaxy:mitre-attack-pattern)"),
      eventId: z.string().optional().describe("Specific event ID"),
      org: z.string().optional().describe("Organization filter"),
      dateFrom: z.string().optional().describe("Start date (YYYY-MM-DD)"),
      dateTo: z.string().optional().describe("End date (YYYY-MM-DD)"),
      last: z.string().optional().describe("Relative time (e.g., 1d, 7d, 30d, 6m)"),
      published: z.boolean().optional().describe("Only published events"),
      limit: z.number().optional().describe("Max results (default 50)"),
      page: z.number().optional().describe("Page number for pagination"),
    },
    async (params) => {
      try {
        const events = await client.searchEvents({
          value: params.value,
          type: params.type,
          category: params.category,
          tags: params.tags,
          eventid: params.eventId,
          org: params.org,
          dateFrom: params.dateFrom,
          dateTo: params.dateTo,
          last: params.last,
          published: params.published,
          limit: params.limit,
          page: params.page,
        });

        if (events.length === 0) {
          return {
            content: [{ type: "text", text: "No events found matching the search criteria." }],
          };
        }

        const summary = events.map((e) => ({
          id: e.id,
          info: e.info,
          date: e.date,
          threat_level: ["", "High", "Medium", "Low", "Undefined"][
            parseInt(e.threat_level_id) || 0
          ],
          analysis: ["Initial", "Ongoing", "Complete"][parseInt(e.analysis) || 0],
          published: e.published,
          org: e.Orgc?.name || "Unknown",
          attribute_count: e.attribute_count,
          tags: (e.Tag || []).map((t) => t.name),
        }));

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(summary, null, 2),
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error searching events: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Get event details
  server.tool(
    "misp_get_event",
    "Get full details of a specific MISP event including all attributes, objects, tags, and related events",
    {
      eventId: z.string().describe("Event ID to retrieve"),
    },
    async ({ eventId }) => {
      try {
        const event = await client.getEvent(eventId);

        const result = {
          id: event.id,
          uuid: event.uuid,
          info: event.info,
          date: event.date,
          threat_level: ["", "High", "Medium", "Low", "Undefined"][
            parseInt(event.threat_level_id) || 0
          ],
          analysis: ["Initial", "Ongoing", "Complete"][parseInt(event.analysis) || 0],
          distribution: ["Organization", "Community", "Connected communities", "All communities", "Sharing group"][
            parseInt(event.distribution) || 0
          ],
          published: event.published,
          org: event.Orgc?.name || "Unknown",
          tags: (event.Tag || []).map((t) => t.name),
          attribute_count: event.attribute_count,
          attributes: (event.Attribute || []).map((a) => ({
            id: a.id,
            type: a.type,
            category: a.category,
            value: a.value,
            to_ids: a.to_ids,
            comment: a.comment,
          })),
          objects: (event.Object || []).map((o) => ({
            id: o.id,
            name: o.name,
            meta_category: o.meta_category,
            attributes: (o.Attribute || []).map((a) => ({
              type: a.type,
              value: a.value,
            })),
          })),
          galaxies: (event.Galaxy || []).map((g) => ({
            name: g.name,
            type: g.type,
            clusters: (g.GalaxyCluster || []).map((c) => c.value),
          })),
          related_events: (event.RelatedEvent || []).map((r) => ({
            id: r.Event.id,
            info: r.Event.info,
            date: r.Event.date,
          })),
        };

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error getting event: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Create event
  server.tool(
    "misp_create_event",
    "Create a new MISP event for documenting incidents or threat intelligence. Does not publish - use misp_publish_event separately.",
    {
      info: z.string().describe("Event description/title"),
      distribution: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3), z.literal(4)])
        .describe("0=Organization only, 1=Community, 2=Connected communities, 3=All communities, 4=Sharing group"),
      threatLevel: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)])
        .describe("1=High, 2=Medium, 3=Low, 4=Undefined"),
      analysis: z.union([z.literal(0), z.literal(1), z.literal(2)])
        .describe("0=Initial, 1=Ongoing, 2=Complete"),
      date: z.string().optional().describe("Event date (YYYY-MM-DD)"),
      tags: z.array(z.string()).optional().describe("Tags to apply"),
    },
    async (params) => {
      try {
        const event = await client.createEvent({
          info: params.info,
          distribution: params.distribution,
          threat_level_id: params.threatLevel,
          analysis: params.analysis,
          date: params.date,
          tags: params.tags,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  id: event.id,
                  uuid: event.uuid,
                  info: event.info,
                  date: event.date,
                  published: event.published,
                  tags: (event.Tag || []).map((t) => t.name),
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
            { type: "text", text: `Error creating event: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Update event
  server.tool(
    "misp_update_event",
    "Update an existing MISP event's metadata (info, threat level, analysis status). Publishing is separate - use misp_publish_event.",
    {
      eventId: z.string().describe("Event ID to update"),
      info: z.string().optional().describe("New event description"),
      threatLevel: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional()
        .describe("1=High, 2=Medium, 3=Low, 4=Undefined"),
      analysis: z.union([z.literal(0), z.literal(1), z.literal(2)]).optional()
        .describe("0=Initial, 1=Ongoing, 2=Complete"),
    },
    async ({ eventId, info, threatLevel, analysis }) => {
      try {
        const event = await client.updateEvent(eventId, {
          info,
          threat_level_id: threatLevel,
          analysis,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  id: event.id,
                  info: event.info,
                  threat_level_id: event.threat_level_id,
                  analysis: event.analysis,
                  published: event.published,
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
            { type: "text", text: `Error updating event: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Publish event
  server.tool(
    "misp_publish_event",
    "Publish a MISP event, triggering alerts and notifications to sharing partners",
    {
      eventId: z.string().describe("Event ID to publish"),
    },
    async ({ eventId }) => {
      try {
        const result = await client.publishEvent(eventId);
        return {
          content: [
            { type: "text", text: result.message || `Event ${eventId} published successfully.` },
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error publishing event: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Tag event
  server.tool(
    "misp_tag_event",
    "Add or remove a tag from a MISP event (TLP, MITRE ATT&CK, custom tags)",
    {
      eventId: z.string().describe("Event ID to tag"),
      tag: z.string().describe("Tag name (e.g., tlp:white, misp-galaxy:mitre-attack-pattern)"),
      remove: z.boolean().optional().describe("Set to true to remove the tag instead of adding"),
    },
    async ({ eventId, tag, remove }) => {
      try {
        if (remove) {
          await client.untagEvent(eventId, tag);
          return {
            content: [
              { type: "text", text: `Tag "${tag}" removed from event ${eventId}.` },
            ],
          };
        } else {
          await client.tagEvent(eventId, tag);
          return {
            content: [
              { type: "text", text: `Tag "${tag}" added to event ${eventId}.` },
            ],
          };
        }
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error tagging event: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
