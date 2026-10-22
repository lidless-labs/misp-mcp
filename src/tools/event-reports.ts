import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { createMutationPolicy, type MutationPolicy } from "../guards.js";
import {
  DEFAULT_SEARCH_LIMIT,
  EVENT_REPORT_MAX_CONTENT_BYTES,
  EVENT_REPORT_MAX_RETURNED_CHARS,
  limitInput,
  SEARCH_LIMIT_MAX,
} from "../limits.js";
import { ToolRegistry } from "../tool-registry.js";
import { trustedText } from "../untrusted.js";

const DISTRIBUTION_LABELS = ["Organization", "Community", "Connected communities", "All communities", "Sharing group", "Inherit event"];

export function registerEventReportTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  // List event reports for an event
  tools.add(
    "misp_list_event_reports",
    `List the event reports (Markdown investigation narratives) attached to an event, without their content. The request is scoped to this event on the MISP side and the result is bounded by limit (default ${DEFAULT_SEARCH_LIMIT}, max ${SEARCH_LIMIT_MAX}). Use misp_get_event_report to read one.`,
    {
      eventId: z.string().describe("Event ID to list reports for"),
      limit: limitInput(),
    },
    async ({ eventId, limit }) => {
      try {
        const all = await client.listEventReports(eventId);

        if (all.length === 0) {
          return {
            content: [{ type: "text", text: `No event reports found for event ${eventId}.` }],
          };
        }

        const cap = limit ?? DEFAULT_SEARCH_LIMIT;
        const shown = all.slice(0, cap);
        const summary = shown.map((r) => ({
          id: r.id,
          uuid: r.uuid,
          event_id: r.event_id,
          name: r.name,
          distribution: DISTRIBUTION_LABELS[parseInt(r.distribution, 10)] ?? r.distribution,
          timestamp: r.timestamp,
        }));

        return {
          content: [
            { type: "text", text: JSON.stringify(summary, null, 2) },
            ...(all.length > shown.length
              ? [trustedText(`Note: showing the first ${shown.length} of ${all.length} reports. Raise limit (max ${SEARCH_LIMIT_MAX}) to see more.`)]
              : []),
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error listing event reports: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Get one event report
  tools.add(
    "misp_get_event_report",
    `Get one event report by ID, including its Markdown content (content longer than ${EVENT_REPORT_MAX_RETURNED_CHARS} characters is cut and the result says so).`,
    {
      eventReportId: z.string().describe("Event report ID to retrieve"),
    },
    async ({ eventReportId }) => {
      try {
        const r = await client.getEventReport(eventReportId);
        const content = r.content ?? "";
        const truncated = content.length > EVENT_REPORT_MAX_RETURNED_CHARS;

        const result = {
          id: r.id,
          uuid: r.uuid,
          event_id: r.event_id,
          name: r.name,
          distribution: DISTRIBUTION_LABELS[parseInt(r.distribution, 10)] ?? r.distribution,
          timestamp: r.timestamp,
          content: truncated ? content.slice(0, EVENT_REPORT_MAX_RETURNED_CHARS) : content,
        };

        return {
          content: [
            { type: "text", text: JSON.stringify(result, null, 2) },
            ...(truncated
              ? [trustedText(`Note: content was cut to ${EVENT_REPORT_MAX_RETURNED_CHARS} of ${content.length} characters.`)]
              : []),
          ],
        };
      } catch (err) {
        return {
          content: [
            { type: "text", text: `Error getting event report: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );

  // Add an event report
  tools.add(
    "misp_add_event_report",
    `Add a Markdown event report to an event to record the written narrative of an investigation. Additive: it does not change or delete existing reports. content is capped at 1 MB (${EVENT_REPORT_MAX_CONTENT_BYTES} bytes). When distribution is omitted MISP applies the event's own setting.`,
    {
      eventId: z.string().describe("Event ID to attach the report to"),
      name: z.string().min(1).max(255).describe("Report title"),
      content: z
        .string()
        .min(1)
        .refine((value) => Buffer.byteLength(value, "utf8") <= EVENT_REPORT_MAX_CONTENT_BYTES, {
          message: `content must be at most ${EVENT_REPORT_MAX_CONTENT_BYTES} bytes (1 MB)`,
        })
        .describe("Report body in Markdown (max 1 MB)"),
      distribution: z
        .number()
        .int()
        .min(0)
        .max(5)
        .refine((level) => level !== 4, "Distribution 4 (sharing group) needs a sharing group ID, which this tool does not accept")
        .optional()
        .describe("0=Organization only, 1=Community, 2=Connected communities, 3=All communities, 5=Inherit from the event. Level 4 (sharing group) is not supported. Omit to use the server default."),
    },
    async ({ eventId, name, content, distribution }) => {
      try {
        const report = await client.addEventReport(eventId, { name, content, distribution });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  id: report.id,
                  uuid: report.uuid,
                  event_id: report.event_id,
                  name: report.name,
                  distribution: DISTRIBUTION_LABELS[parseInt(report.distribution, 10)] ?? report.distribution,
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
            { type: "text", text: `Error adding event report: ${err instanceof Error ? err.message : String(err)}` },
          ],
          isError: true,
        };
      }
    }
  );
}
