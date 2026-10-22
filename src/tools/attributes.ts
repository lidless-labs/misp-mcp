import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { limitInput, moreResultsNote, pageInput, BULK_CONFIRM_THRESHOLD, BULK_MAX_ATTRIBUTES, BULK_MAX_CONSECUTIVE_FAILURES, MAX_TAGS_PER_CALL } from "../limits.js";
import { ToolRegistry } from "../tool-registry.js";
import { trustedText } from "../untrusted.js";
import { requireConfirmation, requireHardConfirmation, createMutationPolicy, type MutationPolicy } from "../guards.js";

const UPDATE_FIELD_NAMES = ["value", "type", "category", "toIds", "comment", "disableCorrelation", "distribution"] as const;

const missingUpdateFields = (params: Record<string, unknown>): string | undefined =>
  UPDATE_FIELD_NAMES.every((name) => params[name] === undefined)
    ? `Provide at least one field to update: ${UPDATE_FIELD_NAMES.join(", ")}.`
    : undefined;

export function registerAttributeTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  // Search attributes
  tools.add(
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
      limit: limitInput(),
      page: pageInput(),
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
          page: params.page,
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

        const note = moreResultsNote(attributes.length, params.limit, params.page);
        return {
          content: [
            { type: "text", text: JSON.stringify(summary, null, 2) },
            ...(note ? [trustedText(note)] : []),
          ],
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

  // Get one attribute
  tools.add(
    "misp_get_attribute",
    "Get one MISP attribute (IOC) by ID, including its tags",
    {
      attributeId: z.string().describe("Attribute ID to retrieve"),
    },
    async ({ attributeId }) => {
      try {
        const a = await client.getAttribute(attributeId);

        const result = {
          id: a.id,
          event_id: a.event_id,
          uuid: a.uuid,
          type: a.type,
          category: a.category,
          value: a.value,
          to_ids: a.to_ids,
          comment: a.comment || undefined,
          distribution: a.distribution,
          timestamp: a.timestamp,
          disable_correlation: a.disable_correlation,
          deleted: a.deleted,
          tags: (a.Tag || []).map((t) => t.name),
        };

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error getting attribute: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Update attribute
  tools.add(
    "misp_update_attribute",
    "Edit selected fields of an existing MISP attribute in place (value, type, category, to_ids, comment, disable_correlation, distribution). Keeps the attribute's history, sightings, and correlations. At least one field is required; the owning event cannot be changed.",
    {
      attributeId: z.string().describe("Attribute ID to update"),
      value: z.string().min(1).optional().describe("New IOC value"),
      type: z.string().min(1).optional().describe("New attribute type"),
      category: z.string().min(1).optional().describe("New category"),
      toIds: z.boolean().optional().describe("Set or clear the IDS flag"),
      comment: z.string().optional().describe("New comment (empty string clears it)"),
      disableCorrelation: z.boolean().optional().describe("Disable or enable correlation for this attribute"),
      distribution: z
        .number()
        .int()
        .min(0)
        .max(5)
        .refine((level) => level !== 4, "Distribution 4 (sharing group) needs a sharing group ID, which this tool does not accept")
        .optional()
        .describe("Distribution level: 0 organisation only, 1 community, 2 connected communities, 3 all communities, 5 inherit from the event. Level 4 (sharing group) is not supported here."),
    },
    async ({ attributeId, value, type, category, toIds, comment, disableCorrelation, distribution }) => {
      try {
        const fields = { value, type, category, to_ids: toIds, comment, disable_correlation: disableCorrelation, distribution };
        const missing = missingUpdateFields({ value, type, category, toIds, comment, disableCorrelation, distribution });
        if (missing) {
          return { content: [{ type: "text", text: missing }], isError: true };
        }

        const attribute = await client.updateAttribute(attributeId, fields);

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
                  comment: attribute.comment || undefined,
                  distribution: attribute.distribution,
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
            { type: "text", text: `Error updating attribute: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    },
    missingUpdateFields
  );

  // Add attribute
  tools.add(
    "misp_add_attribute",
    "Add an IOC/attribute to a MISP event",
    {
      eventId: z.string().describe("Event ID to add the attribute to"),
      type: z.string().describe("Attribute type (ip-src, ip-dst, domain, md5, sha256, sha1, url, email-src, hostname, filename, etc.)"),
      value: z.string().describe("The IOC value"),
      category: z.string().optional().describe("Category (auto-determined from type if omitted)"),
      toIds: z.boolean().optional().describe("Flag for IDS export (default true for applicable types)"),
      comment: z.string().optional().describe("Context/notes about this IOC"),
      distribution: z.number().int().min(0).max(5).optional().describe("Distribution level (0-4, or 5 to inherit from the event)"),
      tags: z.array(z.string()).max(MAX_TAGS_PER_CALL).optional().describe(`Tags to apply to the attribute (max ${MAX_TAGS_PER_CALL})`),
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
  tools.add(
    "misp_add_attributes_bulk",
    `Add multiple attributes (IOCs) to a MISP event at once (max ${BULK_MAX_ATTRIBUTES} per call; more than ${BULK_CONFIRM_THRESHOLD} requires confirm:true). Each attribute is a separate MISP request, so a failure partway leaves the event partially updated; the result lists what succeeded, failed, and was skipped. Use dryRun:true to preview.`,
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
      ).min(1).max(BULK_MAX_ATTRIBUTES).describe(`Array of attributes to add (1-${BULK_MAX_ATTRIBUTES})`),
      confirm: z.boolean().optional().describe(`Must be true when adding more than ${BULK_CONFIRM_THRESHOLD} attributes`),
    },
    async ({ eventId, attributes, confirm }) => {
      try {
        if (attributes.length > BULK_CONFIRM_THRESHOLD) {
          const guard = requireConfirmation(
            confirm,
            `adding ${attributes.length} attributes in one call (bulk writes above ${BULK_CONFIRM_THRESHOLD} attributes)`
          );
          if (guard) return guard;
        }

        const results: Array<{ value: string; type: string; id?: string; error?: string; skipped?: boolean }> = [];
        let consecutiveFailures = 0;

        for (const attr of attributes) {
          if (consecutiveFailures >= BULK_MAX_CONSECUTIVE_FAILURES) {
            results.push({ value: attr.value, type: attr.type, skipped: true });
            continue;
          }
          try {
            const created = await client.addAttribute(eventId, {
              type: attr.type,
              value: attr.value,
              category: attr.category,
              to_ids: attr.toIds,
              comment: attr.comment,
            });
            consecutiveFailures = 0;
            results.push({
              value: attr.value,
              type: attr.type,
              id: created.id,
            });
          } catch (err) {
            consecutiveFailures++;
            results.push({
              value: attr.value,
              type: attr.type,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }

        const succeeded = results.filter((r) => r.id);
        const failed = results.filter((r) => r.error);
        const skipped = results.filter((r) => r.skipped);
        const warnings: string[] = [];
        if (failed.length > 0 || skipped.length > 0) {
          warnings.push(
            `Partial result: ${succeeded.length} of ${attributes.length} attributes were added to event ${eventId}. ` +
              "The ones that succeeded were not rolled back."
          );
        }
        if (skipped.length > 0) {
          warnings.push(
            `Stopped after ${BULK_MAX_CONSECUTIVE_FAILURES} consecutive failures; ${skipped.length} attributes were not attempted.`
          );
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  total: attributes.length,
                  succeeded: succeeded.length,
                  failed: failed.length,
                  skipped: skipped.length,
                  warnings: warnings.length > 0 ? warnings : undefined,
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
  tools.add(
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
