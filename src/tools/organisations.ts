import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerOrganisationTools(
  server: McpServer,
  client: MispClient
): void {
  // List organisations
  server.tool(
    "misp_list_organisations",
    "List MISP organisations (local and remote sharing partners)",
    {
      scope: z
        .enum(["local", "external", "all"])
        .optional()
        .describe("Filter by local, external, or all organisations"),
    },
    async ({ scope }) => {
      try {
        const orgs = await client.listOrganisations(scope || "all");

        if (orgs.length === 0) {
          return {
            content: [{ type: "text", text: "No organisations found." }],
          };
        }

        const summary = orgs.map((o) => ({
          id: o.id,
          name: o.name,
          uuid: o.uuid,
          description: o.description,
          nationality: o.nationality,
          sector: o.sector,
          type: o.type,
          local: o.local,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error listing organisations: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Get organisation details
  server.tool(
    "misp_get_organisation",
    "Get details of a specific MISP organisation",
    {
      orgId: z.string().describe("Organisation ID"),
    },
    async ({ orgId }) => {
      try {
        const org = await client.getOrganisation(orgId);
        return {
          content: [{ type: "text", text: JSON.stringify(org, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error getting organisation: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );
}
