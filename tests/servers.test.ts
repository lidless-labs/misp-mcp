import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MispClient } from "../src/client.js";
import { registerServerTools } from "../src/tools/servers.js";
import type { MispConfig } from "../src/config.js";

const mockConfig: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-key",
  verifySsl: true,
  timeout: 30000,
};

function createTestHarness() {
  const handlers = new Map<string, (params: Record<string, unknown>) => Promise<unknown>>();
  const mockServer = {
    tool: vi.fn((_name: string, _desc: unknown, schemaOrHandler: unknown, handler?: unknown) => {
      const actualHandler = (handler || schemaOrHandler) as (params: Record<string, unknown>) => Promise<unknown>;
      handlers.set(_name, actualHandler);
    }),
    resource: vi.fn(),
    prompt: vi.fn(),
  } as unknown as McpServer;
  return { mockServer, handlers };
}

function mockFetch(response: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof response === "string" ? response : JSON.stringify(response)),
  });
}

describe("Server Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerServerTools(harness.mockServer, client);
  });

  describe("misp_server_status", () => {
    it("should return server version and permissions", async () => {
      let callCount = 0;
      vi.stubGlobal("fetch", vi.fn().mockImplementation((url: string) => {
        callCount++;
        let body: unknown;
        if (url.includes("getVersion")) {
          body = {
            version: "2.5.35",
            pymisp_recommended_version: "2.5.33.1",
            perm_sync: true,
            perm_sighting: true,
            perm_galaxy_editor: true,
            perm_analyst_data: true,
          };
        } else {
          body = { diagnostics: { php_version: "8.2" } };
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve(JSON.stringify(body)),
        });
      }));

      const handler = handlers.get("misp_server_status")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data.version).toBe("2.5.35");
      expect(data.permissions.sync).toBe(true);
      expect(data.permissions.sighting).toBe(true);
    });
  });

  describe("misp_list_sharing_groups", () => {
    it("should list sharing groups", async () => {
      vi.stubGlobal("fetch", mockFetch({
        response: [
          { SharingGroup: { id: "1", name: "Trusted Partners", description: "Vetted sharing partners", uuid: "sg-1", releasability: "Partner orgs", active: true, org_count: 5 } },
        ],
      }));

      const handler = handlers.get("misp_list_sharing_groups")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].name).toBe("Trusted Partners");
      expect(data[0].org_count).toBe(5);
    });

    it("should handle no sharing groups", async () => {
      vi.stubGlobal("fetch", mockFetch({ response: [] }));
      const handler = handlers.get("misp_list_sharing_groups")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("No sharing groups");
    });
  });

  describe("misp_delete_event", () => {
    it("should delete an event", async () => {
      vi.stubGlobal("fetch", mockFetch({ message: "Event deleted." }));
      const handler = handlers.get("misp_delete_event")!;
      const result = (await handler({ eventId: "42" })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("deleted");
    });

    it("should handle deletion errors", async () => {
      vi.stubGlobal("fetch", mockFetch({ message: "Event not found" }, 404));
      const handler = handlers.get("misp_delete_event")!;
      const result = (await handler({ eventId: "99999" })) as { content: Array<{ text: string }>; isError: boolean };
      expect(result.isError).toBe(true);
    });
  });
});
