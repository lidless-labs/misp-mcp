import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerFeedTools(server: McpServer, client: MispClient): void {
  // List feeds
  server.tool(
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
  server.tool(
    "misp_toggle_feed",
    "Enable or disable a MISP feed",
    {
      feedId: z.string().describe("Feed ID"),
      enable: z.boolean().describe("true to enable, false to disable"),
    },
    async ({ feedId, enable }) => {
      try {
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
  server.tool(
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
  server.tool(
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
