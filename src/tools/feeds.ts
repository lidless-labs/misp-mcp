import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";
import { createMutationPolicy, requireConfirmation, type MutationPolicy } from "../guards.js";
import { ToolRegistry } from "../tool-registry.js";

export function registerFeedTools(
  server: McpServer,
  client: MispClient,
  policy: MutationPolicy = createMutationPolicy()
): void {
  const tools = new ToolRegistry(server, client, policy);

  // List feeds
  tools.add(
    "misp_list_feeds",
    "List configured MISP feeds (threat intel sources, IOC feeds, etc.)",
    {
      enabled: z
        .boolean()
        .optional()
        .describe("Filter by enabled/disabled status"),
    },
    async ({ enabled }) => {
      try {
        let feeds = await client.listFeeds();

        if (enabled !== undefined) {
          feeds = feeds.filter((f) => f.enabled === enabled);
        }

        if (feeds.length === 0) {
          return {
            content: [{ type: "text", text: "No feeds found." }],
          };
        }

        const summary = feeds.map((f) => ({
          id: f.id,
          name: f.name,
          provider: f.provider,
          url: f.url,
          enabled: f.enabled,
          source_format: f.source_format,
          distribution: f.distribution,
          event_id: f.event_id,
          caching_enabled: f.caching_enabled,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error listing feeds: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Enable/disable feed
  tools.add(
    "misp_toggle_feed",
    "Enable or disable a MISP feed. Disabling a feed stops intelligence ingestion and requires confirm:true (or MISP_ALLOW_DESTRUCTIVE=true).",
    {
      feedId: z.string().describe("Feed ID"),
      enable: z.boolean().describe("true to enable, false to disable"),
      confirm: z.boolean().optional().describe("Must be true to disable a feed (unless MISP_ALLOW_DESTRUCTIVE=true). Ignored when enabling."),
    },
    async ({ feedId, enable, confirm }) => {
      try {
        if (!enable) {
          const guard = requireConfirmation(confirm, `disabling feed ${feedId}`);
          if (guard) return guard;
        }

        await client.toggleFeed(feedId, enable);
        return {
          content: [
            {
              type: "text",
              text: `Feed ${feedId} ${enable ? "enabled" : "disabled"} successfully.`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error toggling feed: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Fetch feed data
  tools.add(
    "misp_fetch_feed",
    "Trigger a fetch/pull of data from a specific MISP feed",
    {
      feedId: z.string().describe("Feed ID to fetch"),
    },
    async ({ feedId }) => {
      try {
        const result = await client.fetchFeed(feedId);
        return {
          content: [
            {
              type: "text",
              text: result.message || `Feed ${feedId} fetch initiated.`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error fetching feed: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Cache feed
  tools.add(
    "misp_cache_feed",
    "Cache feed data locally for correlation without creating events",
    {
      feedId: z.string().describe("Feed ID to cache"),
    },
    async ({ feedId }) => {
      try {
        const result = await client.cacheFeed(feedId);
        return {
          content: [
            {
              type: "text",
              text: result.message || `Feed ${feedId} cache initiated.`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error caching feed: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );
}
