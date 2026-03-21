import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerObjectTools(server: McpServer, client: MispClient): void {
  // List object templates
  server.tool(
    "misp_list_object_templates",
    "List available MISP object templates (file, domain-ip, email, network-connection, etc.)",
    {
      search: z.string().optional().describe("Filter templates by name"),
      limit: z.number().optional().describe("Max results (default 50)"),
    },
    async ({ search, limit }) => {
      try {
        const templates = await client.listObjectTemplates();
        let filtered = templates;
        if (search) {
          const q = search.toLowerCase();
          filtered = templates.filter(
            (t) =>
              t.name.toLowerCase().includes(q) ||
              t.description.toLowerCase().includes(q)
          );
        }
        if (limit && limit > 0) {
          filtered = filtered.slice(0, limit);
        }

        if (filtered.length === 0) {
          return {
            content: [{ type: "text", text: "No object templates found." }],
          };
        }

        const summary = filtered.map((t) => ({
          id: t.id,
          uuid: t.uuid,
          name: t.name,
          description: t.description,
          version: t.version,
          meta_category: t.meta_category,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error listing object templates: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Get object template details
  server.tool(
    "misp_get_object_template",
    "Get details of a specific MISP object template including required and optional attributes",
    {
      templateId: z.string().describe("Object template ID or UUID"),
    },
    async ({ templateId }) => {
      try {
        const template = await client.getObjectTemplate(templateId);
        return {
          content: [{ type: "text", text: JSON.stringify(template, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error getting object template: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Add object to event
  server.tool(
    "misp_add_object",
    "Add a MISP object (structured group of attributes) to an event",
    {
      eventId: z.string().describe("Event ID to add the object to"),
      templateName: z
        .string()
        .describe(
          "Object template name (e.g., file, domain-ip, email, network-connection, url)"
        ),
      attributes: z
        .array(
          z.object({
            object_relation: z
              .string()
              .describe(
                "Attribute relation within the object (e.g., filename, md5, ip, domain)"
              ),
            type: z
              .string()
              .describe("Attribute type (ip-dst, domain, md5, filename, etc.)"),
            value: z.string().describe("Attribute value"),
            to_ids: z
              .boolean()
              .optional()
              .describe("Flag for IDS export"),
            comment: z.string().optional().describe("Comment"),
          })
        )
        .describe("Attributes to include in the object"),
      comment: z.string().optional().describe("Object-level comment"),
      distribution: z
        .number()
        .optional()
        .describe("Distribution level (0-4)"),
    },
    async ({ eventId, templateName, attributes, comment, distribution }) => {
      try {
        const result = await client.addObject(eventId, {
          name: templateName,
          attributes,
          comment,
          distribution,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  id: result.id,
                  name: result.name,
                  event_id: result.event_id,
                  meta_category: result.meta_category,
                  description: result.description,
                  attributes: (result.Attribute || []).map((a) => ({
                    type: a.type,
                    object_relation: a.object_relation,
                    value: a.value,
                  })),
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
            {
              type: "text",
              text: `Error adding object: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Delete object
  server.tool(
    "misp_delete_object",
    "Delete a MISP object from an event",
    {
      objectId: z.string().describe("Object ID to delete"),
      hard: z
        .boolean()
        .optional()
        .describe("Hard delete (permanent) instead of soft delete"),
    },
    async ({ objectId, hard }) => {
      try {
        const result = await client.deleteObject(objectId, hard);
        return {
          content: [
            {
              type: "text",
              text:
                result.message ||
                `Object ${objectId} deleted successfully.`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error deleting object: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );
}
