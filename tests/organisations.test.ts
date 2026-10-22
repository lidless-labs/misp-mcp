import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetch } from "undici";

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: vi.fn(),
}));
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MispClient } from "../src/client.js";
import { registerOrganisationTools } from "../src/tools/organisations.js";
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

describe("Organisation Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerOrganisationTools(harness.mockServer, client, ALLOW_ALL_MUTATIONS);
  });

  describe("misp_list_organisations", () => {
    it("should list organisations", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch([
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
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch([]));
      const handler = handlers.get("misp_list_organisations")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("No organisations found");
    });
  });

  describe("misp_get_organisation", () => {
    it("should return organisation details", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({
        Organisation: { id: "1", name: "ADMIN", uuid: "org-1", description: "Admin org", nationality: "US", sector: "Government", type: "ADMIN", local: true },
      }));

      const handler = handlers.get("misp_get_organisation")!;
      const result = (await handler({ orgId: "1" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("ADMIN");
      expect(data.local).toBe(true);
    });

    it("should handle errors", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(vi.fn().mockRejectedValue(new Error("Not found")));
      const handler = handlers.get("misp_get_organisation")!;
      const result = (await handler({ orgId: "999" })) as { content: Array<{ text: string }>; isError: boolean };
      expect(result.isError).toBe(true);
    });
  });
});
