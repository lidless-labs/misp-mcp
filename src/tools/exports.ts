import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { createMutationPolicy, type MutationPolicy } from "../guards.js";
import { ToolRegistry } from "../tool-registry.js";

export function registerExportTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  // Export IOCs
  tools.add(
    "misp_export_iocs",
    "Export IOCs from MISP in various formats (CSV, STIX, Suricata, Snort, text, RPZ)",
    {
      format: z.enum(["csv", "stix", "suricata", "snort", "text", "rpz"])
        .describe("Export format"),
      eventId: z.string().optional().describe("Specific event ID (or all events if omitted)"),
      type: z.string().optional().describe("Filter by attribute type"),
      tags: z.array(z.string()).optional().describe("Filter by tags"),
      last: z.string().optional().describe("Relative time filter (e.g., 1d, 7d)"),
    },
    async (params) => {
      try {
        const output = await client.exportEvents({
          format: params.format,
          eventId: params.eventId,
          type: params.type,
          tags: params.tags,
          last: params.last,
        });

        if (!output || output.trim().length === 0) {
          return {
            content: [
              { type: "text", text: `No IOCs found for the specified criteria in ${params.format} format.` },
            ],
          };
        }

        return {
          content: [{ type: "text", text: output }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error exporting IOCs: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Export hashes
  tools.add(
    "misp_export_hashes",
    "Export file hashes from MISP for HIDS integration",
    {
      format: z.enum(["md5", "sha1", "sha256"]).describe("Hash format to export"),
      last: z.string().optional().describe("Relative time filter (e.g., 1d, 7d)"),
      tags: z.array(z.string()).optional().describe("Filter by tags"),
    },
    async (params) => {
      try {
        const output = await client.exportHashes({
          format: params.format,
          last: params.last,
          tags: params.tags,
        });

        if (!output || output.trim().length === 0) {
          return {
            content: [
              { type: "text", text: `No ${params.format} hashes found for the specified criteria.` },
            ],
          };
        }

        return {
          content: [{ type: "text", text: output }],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error exporting hashes: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
