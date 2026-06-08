import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { requireConfirmation, requireHardConfirmation } from "../guards.js";

export function registerAttributeTools(server: McpServer, client: MispClient): void {
  // Search attributes
  server.tool(
    "misp_search_attributes",
    "Search for specific attributes (IOCs) across all MISP events",
    {
      value: z.string().optional().describe("IOC value to search"),
      type: z.string().optional().describe("Attribute type (ip-src, ip-dst, domain, md5, sha256, url, email-src, hostname, etc.)"),
      category: z.string().optional().describe("Category filter"),
      tags: z.array(z.string()).optional().describe("Tag filters"),
      toIds: z.boolean().optional().describe("Only IDS-flagged attributes"),
      includeCorrelations: z.boolean().optional().describe("Include correlation data"),
      last: z.string().optional().describe("Relative time filter (e.g., 1d, 7d, 30d)"),
      limit: z.number().optional().describe("Max results (default 50)"),
    },
    async (params) => {
      try {
        const attributes = await client.searchAttributes({
          value: params.value,
          type: params.type,
          category: params.category,
          tags: params.tags,
          to_ids: params.toIds,
          includeCorrelations: params.includeCorrelations,
          last: params.last,
          limit: params.limit,
        });

        if (attributes.length === 0) {
          return {
            content: [{ type: "text", text: "No attributes found matching the search criteria." }],
          };
        }

        const summary = attributes.map((a) => ({
          id: a.id,
          event_id: a.event_id,
          type: a.type,
          category: a.category,
          value: a.value,
          to_ids: a.to_ids,
          comment: a.comment || undefined,
          tags: (a.Tag || []).map((t) => t.name),
          event_info: a.Event?.info,
          correlations: a.RelatedAttribute
            ? a.RelatedAttribute.map((r) => ({
                value: r.value,
                type: r.type,
                event_id: r.event_id,
              }))
            : undefined,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error searching attributes: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Add attribute
  server.tool(
    "misp_add_attribute",
    "Add an IOC/attribute to a MISP event",
    {
      eventId: z.string().describe("Event ID to add the attribute to"),
      type: z.string().describe("Attribute type (ip-src, ip-dst, domain, md5, sha256, sha1, url, email-src, hostname, filename, etc.)"),
      value: z.string().describe("The IOC value"),
      category: z.string().optional().describe("Category (auto-determined from type if omitted)"),
      toIds: z.boolean().optional().describe("Flag for IDS export (default true for applicable types)"),
      comment: z.string().optional().describe("Context/notes about this IOC"),
      distribution: z.number().optional().describe("Distribution level (0-4)"),
      tags: z.array(z.string()).optional().describe("Tags to apply to the attribute"),
    },
    async (params) => {
      try {
        const attribute = await client.addAttribute(params.eventId, {
          type: params.type,
          value: params.value,
          category: params.category,
          to_ids: params.toIds,
          comment: params.comment,
          distribution: params.distribution,
          tags: params.tags,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  id: attribute.id,
                  event_id: attribute.event_id,
                  type: attribute.type,
                  category: attribute.category,
                  value: attribute.value,
                  to_ids: attribute.to_ids,
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
            { type: "text", text: `Error adding attribute: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Bulk add attributes
  server.tool(
    "misp_add_attributes_bulk",
    "Add multiple attributes (IOCs) to a MISP event at once",
    {
      eventId: z.string().describe("Event ID to add attributes to"),
      attributes: z.array(
        z.object({
          type: z.string().describe("Attribute type"),
          value: z.string().describe("IOC value"),
          category: z.string().optional().describe("Category"),
          toIds: z.boolean().optional().describe("IDS flag"),
          comment: z.string().optional().describe("Comment"),
        })
      ).describe("Array of attributes to add"),
    },
    async ({ eventId, attributes }) => {
      try {
        const results: Array<{ value: string; type: string; id?: string; error?: string }> = [];

        for (const attr of attributes) {
          try {
            const created = await client.addAttribute(eventId, {
              type: attr.type,
              value: attr.value,
              category: attr.category,
              to_ids: attr.toIds,
              comment: attr.comment,
            });
            results.push({
              value: attr.value,
              type: attr.type,
              id: created.id,
            });
          } catch (err) {
            results.push({
              value: attr.value,
              type: attr.type,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }

        const succeeded = results.filter((r) => r.id);
        const failed = results.filter((r) => r.error);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  total: attributes.length,
                  succeeded: succeeded.length,
                  failed: failed.length,
                  results,
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
            { type: "text", text: `Error adding attributes: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Delete attribute
  server.tool(
    "misp_delete_attribute",
    "Delete (soft or hard) an attribute from MISP. Destructive: requires confirm:true (or MISP_ALLOW_DESTRUCTIVE=true); hard delete also requires confirmHard:true.",
    {
      attributeId: z.string().describe("Attribute ID to delete"),
      hard: z.boolean().optional().describe("Hard delete (permanent) instead of soft delete"),
      confirm: z.boolean().optional().describe("Must be true to perform this destructive deletion (unless MISP_ALLOW_DESTRUCTIVE=true)"),
      confirmHard: z.boolean().optional().describe("Must be true (in addition to confirm) to perform a permanent hard delete"),
    },
    async ({ attributeId, hard, confirm, confirmHard }) => {
      try {
        const guard = requireConfirmation(confirm, `deleting attribute ${attributeId}`);
        if (guard) return guard;
        if (hard) {
          const hardGuard = requireHardConfirmation(
            confirmHard,
            `hard-deleting attribute ${attributeId}`
          );
          if (hardGuard) return hardGuard;
        }

        const result = await client.deleteAttribute(attributeId, hard);
        return {
          content: [
            { type: "text", text: result.message || `Attribute ${attributeId} deleted successfully.` },
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error deleting attribute: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
