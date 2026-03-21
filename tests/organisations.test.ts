import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MispClient } from "../src/client.js";
import { registerOrganisationTools } from "../src/tools/organisations.js";
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

describe("Organisation Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerOrganisationTools(harness.mockServer, client);
  });

  describe("misp_list_organisations", () => {
    it("should list organisations", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { Organisation: { id: "1", name: "ADMIN", uuid: "org-1", description: "Admin org", nationality: "US", sector: "Government", type: "ADMIN", local: true } },
        { Organisation: { id: "2", name: "CERT-EU", uuid: "org-2", description: "European CERT", nationality: "EU", sector: "Government", type: "CSIRT", local: false } },
      ]));

      const handler = handlers.get("misp_list_organisations")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(2);
      expect(data[0].name).toBe("ADMIN");
    });

    it("should handle no organisations", async () => {
      vi.stubGlobal("fetch", mockFetch([]));
      const handler = handlers.get("misp_list_organisations")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("No organisations found");
    });
  });

  describe("misp_get_organisation", () => {
    it("should return organisation details", async () => {
      vi.stubGlobal("fetch", mockFetch({
        Organisation: { id: "1", name: "ADMIN", uuid: "org-1", description: "Admin org", nationality: "US", sector: "Government", type: "ADMIN", local: true },
      }));

      const handler = handlers.get("misp_get_organisation")!;
      const result = (await handler({ orgId: "1" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("ADMIN");
      expect(data.local).toBe(true);
    });

    it("should handle errors", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Not found")));
      const handler = handlers.get("misp_get_organisation")!;
      const result = (await handler({ orgId: "999" })) as { content: Array<{ text: string }>; isError: boolean };
      expect(result.isError).toBe(true);
    });
  });
});
