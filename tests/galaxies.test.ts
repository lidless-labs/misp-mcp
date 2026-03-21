import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MispClient } from "../src/client.js";
import { registerGalaxyTools } from "../src/tools/galaxies.js";
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

describe("Galaxy Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerGalaxyTools(harness.mockServer, client);
  });

  describe("misp_list_galaxies", () => {
    it("should list all galaxies", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { Galaxy: { id: "39", name: "Attack Pattern", type: "mitre-attack-pattern", description: "MITRE ATT&CK patterns", uuid: "g-39" } },
        { Galaxy: { id: "57", name: "Intrusion Set", type: "mitre-intrusion-set", description: "Threat groups", uuid: "g-57" } },
        { Galaxy: { id: "58", name: "Malware", type: "mitre-malware", description: "Malware families", uuid: "g-58" } },
      ]));

      const handler = handlers.get("misp_list_galaxies")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(3);
    });

    it("should filter by search term", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { Galaxy: { id: "39", name: "Attack Pattern", type: "mitre-attack-pattern", description: "MITRE ATT&CK patterns", uuid: "g-39" } },
        { Galaxy: { id: "57", name: "Intrusion Set", type: "mitre-intrusion-set", description: "Threat groups", uuid: "g-57" } },
      ]));

      const handler = handlers.get("misp_list_galaxies")!;
      const result = (await handler({ search: "intrusion" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].name).toBe("Intrusion Set");
    });

    it("should filter by namespace", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { Galaxy: { id: "39", name: "Attack Pattern", type: "mitre-attack-pattern", description: "Patterns", uuid: "g-39" } },
        { Galaxy: { id: "57", name: "Intrusion Set", type: "mitre-intrusion-set", description: "Groups", uuid: "g-57" } },
      ]));

      const handler = handlers.get("misp_list_galaxies")!;
      const result = (await handler({ namespace: "attack-pattern" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].type).toContain("attack-pattern");
    });
  });

  describe("misp_get_galaxy", () => {
    it("should return galaxy with clusters", async () => {
      vi.stubGlobal("fetch", mockFetch({
        Galaxy: { id: "39", uuid: "g-39", name: "Attack Pattern", type: "mitre-attack-pattern", description: "MITRE ATT&CK" },
        GalaxyCluster: [
          { id: "1", uuid: "c-1", type: "mitre-attack-pattern", value: "T1566 - Phishing", tag_name: "misp-galaxy:mitre-attack-pattern=\"T1566\"", description: "Phishing technique", galaxy_id: "39" },
          { id: "2", uuid: "c-2", type: "mitre-attack-pattern", value: "T1059 - Command and Scripting Interpreter", tag_name: "misp-galaxy:mitre-attack-pattern=\"T1059\"", description: "Script execution", galaxy_id: "39" },
        ],
      }));

      const handler = handlers.get("misp_get_galaxy")!;
      const result = (await handler({ galaxyId: "39" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("Attack Pattern");
      expect(data.cluster_count).toBe(2);
      expect(data.clusters[0].value).toContain("T1566");
    });
  });

  describe("misp_search_galaxy_clusters", () => {
    it("should search clusters by keyword", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { GalaxyCluster: { id: "1", uuid: "c-1", type: "mitre-attack-pattern", value: "T1566 - Phishing", tag_name: "misp-galaxy:mitre-attack-pattern=\"T1566\"", description: "Adversaries may send phishing messages", galaxy_id: "39" } },
        { GalaxyCluster: { id: "2", uuid: "c-2", type: "mitre-attack-pattern", value: "T1566.001 - Spearphishing Attachment", tag_name: "misp-galaxy:mitre-attack-pattern=\"T1566.001\"", description: "Spearphishing with attachments", galaxy_id: "39" } },
      ]));

      const handler = handlers.get("misp_search_galaxy_clusters")!;
      const result = (await handler({ search: "phishing" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(2);
      expect(data[0].value).toContain("Phishing");
    });

    it("should handle no results", async () => {
      vi.stubGlobal("fetch", mockFetch([]));
      const handler = handlers.get("misp_search_galaxy_clusters")!;
      const result = (await handler({ search: "nonexistent" })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("No galaxy clusters found");
    });
  });

  describe("misp_attach_galaxy_cluster", () => {
    it("should attach a cluster to an event", async () => {
      vi.stubGlobal("fetch", mockFetch({ saved: true }));
      const handler = handlers.get("misp_attach_galaxy_cluster")!;
      const result = (await handler({
        targetType: "event",
        targetId: "42",
        galaxyClusterId: "1",
      })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("attached");
    });

    it("should attach a cluster to an attribute", async () => {
      vi.stubGlobal("fetch", mockFetch({ saved: true }));
      const handler = handlers.get("misp_attach_galaxy_cluster")!;
      const result = (await handler({
        targetType: "attribute",
        targetId: "200",
        galaxyClusterId: "5",
      })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("attached");
      expect(result.content[0].text).toContain("attribute");
    });
  });
});
