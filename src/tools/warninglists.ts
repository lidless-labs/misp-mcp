import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { createMutationPolicy, type MutationPolicy } from "../guards.js";
import { ToolRegistry } from "../tool-registry.js";

export function registerWarninglistTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  tools.add(
    "misp_check_warninglists",
    "Check if an observable value appears on any MISP warninglists (known benign/false positive lists)",
    {
      value: z.string().describe("Value to check against warninglists (IP, domain, hash, etc.)"),
    },
    async ({ value }) => {
      try {
        const results = await client.checkWarninglists(value);

        // The API returns a map of value -> matching warninglists
        const matches = results[value] || [];

        if (matches.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `"${value}" does not appear on any warninglists. This does not confirm it is malicious, but it is not a known benign indicator.`,
              },
            ],
          };
        }

        const summary = matches.map((w) => ({
          name: w.name,
          category: w.category,
          description: w.description,
          type: w.type,
        }));

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  value,
                  on_warninglists: true,
                  match_count: matches.length,
                  warninglists: summary,
                  note: "This value appears on known benign/false positive lists. Exercise caution before treating it as malicious.",
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
            { type: "text", text: `Error checking warninglists: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
