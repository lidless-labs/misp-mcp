import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerServerTools(
  server: McpServer,
  client: MispClient
): void {
  // Server status/version
  server.tool(
    "misp_server_status",
    "Get MISP server version, status, and diagnostic information",
    {},
    async () => {
      try {
        const version = await client.getVersion();
        const settings = await client.getServerSettings();

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  version: version.version,
                  pymisp_recommended: version.pymisp_recommended_version,
                  permissions: {
                    sync: version.perm_sync,
                    sighting: version.perm_sighting,
                    galaxy_editor: version.perm_galaxy_editor,
                    analyst_data: version.perm_analyst_data,
                  },
                  diagnostics: settings.diagnostics,
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
              text: `Error getting server status: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // List sharing groups
  server.tool(
    "misp_list_sharing_groups",
    "List MISP sharing groups for controlled event distribution",
    {},
    async () => {
      try {
        const groups = await client.listSharingGroups();

        if (groups.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: "No sharing groups configured.",
              },
            ],
          };
        }

        const summary = groups.map((g) => ({
          id: g.id,
          name: g.name,
          description: g.description,
          uuid: g.uuid,
          releasability: g.releasability,
          active: g.active,
          org_count: g.org_count,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error listing sharing groups: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Delete event
  server.tool(
    "misp_delete_event",
    "Delete a MISP event (requires appropriate permissions)",
    {
      eventId: z.string().describe("Event ID to delete"),
    },
    async ({ eventId }) => {
      try {
        const result = await client.deleteEvent(eventId);
        return {
          content: [
            {
              type: "text",
              text: result.message || `Event ${eventId} deleted.`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error deleting event: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );
}
