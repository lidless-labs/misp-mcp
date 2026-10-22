import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetch } from "undici";

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: vi.fn(),
}));
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MispClient } from "../src/client.js";
import { registerFeedTools } from "../src/tools/feeds.js";
import type { MispConfig } from "../src/config.js";
import { ALLOW_ALL_MUTATIONS } from "../src/guards.js";
import { createToolHarness } from "./helpers.js";

const mockConfig: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-key",
  verifySsl: true,
  timeout: 30000,
};

function createTestHarness() {
  return createToolHarness();
}

function mockFetch(response: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof response === "string" ? response : JSON.stringify(response)),
  });
}

describe("Feed Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerFeedTools(harness.mockServer, client, ALLOW_ALL_MUTATIONS);
  });

  describe("misp_list_feeds", () => {
    it("should list all feeds", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch([
        { Feed: { id: "1", name: "CIRCL OSINT", provider: "CIRCL", url: "https://www.circl.lu/doc/misp/feed-osint", enabled: true, source_format: "misp", distribution: "3", event_id: "0", caching_enabled: true } },
        { Feed: { id: "2", name: "Botvrij.eu", provider: "Botvrij", url: "https://www.botvrij.eu/data/feed-osint", enabled: false, source_format: "misp", distribution: "3", event_id: "0", caching_enabled: false } },
      ]));

      const handler = handlers.get("misp_list_feeds")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(2);
      expect(data[0].name).toBe("CIRCL OSINT");
    });

    it("should filter by enabled status", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch([
        { Feed: { id: "1", name: "CIRCL OSINT", provider: "CIRCL", url: "https://circl.lu", enabled: true, source_format: "misp", distribution: "3", event_id: "0", caching_enabled: true } },
        { Feed: { id: "2", name: "Botvrij.eu", provider: "Botvrij", url: "https://botvrij.eu", enabled: false, source_format: "misp", distribution: "3", event_id: "0", caching_enabled: false } },
      ]));

      const handler = handlers.get("misp_list_feeds")!;
      const result = (await handler({ enabled: true })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].enabled).toBe(true);
    });

    it("should handle no feeds", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch([]));
      const handler = handlers.get("misp_list_feeds")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("No feeds found");
    });
  });

  describe("misp_toggle_feed", () => {
    it("should enable a feed", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Feed enabled." }));
      const handler = handlers.get("misp_toggle_feed")!;
      const result = (await handler({ feedId: "1", enable: true })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("enabled");
    });

    it("should disable a feed", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Feed disabled." }));
      const handler = handlers.get("misp_toggle_feed")!;
      const result = (await handler({ feedId: "1", enable: false, confirm: true })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("disabled");
    });
  });

  describe("misp_fetch_feed", () => {
    it("should trigger a feed fetch", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Feed fetch initiated." }));
      const handler = handlers.get("misp_fetch_feed")!;
      const result = (await handler({ feedId: "1" })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("fetch");
    });
  });

  describe("misp_cache_feed", () => {
    it("should trigger feed caching", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Feed cache initiated." }));
      const handler = handlers.get("misp_cache_feed")!;
      const result = (await handler({ feedId: "1" })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("cache");
    });
  });
});
