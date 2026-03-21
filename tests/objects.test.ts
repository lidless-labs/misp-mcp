import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MispClient } from "../src/client.js";
import { registerObjectTools } from "../src/tools/objects.js";
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

describe("Object Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerObjectTools(harness.mockServer, client);
  });

  describe("misp_list_object_templates", () => {
    it("should list object templates", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { ObjectTemplate: { id: "1", uuid: "t-1", name: "file", description: "File object", version: "24", meta_category: "file" } },
        { ObjectTemplate: { id: "2", uuid: "t-2", name: "domain-ip", description: "Domain-IP", version: "10", meta_category: "network" } },
      ]));

      const handler = handlers.get("misp_list_object_templates")!;
      const result = (await handler({})) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(2);
      expect(data[0].name).toBe("file");
    });

    it("should filter by search term", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { ObjectTemplate: { id: "1", uuid: "t-1", name: "file", description: "File object", version: "24", meta_category: "file" } },
        { ObjectTemplate: { id: "2", uuid: "t-2", name: "domain-ip", description: "Domain-IP", version: "10", meta_category: "network" } },
      ]));

      const handler = handlers.get("misp_list_object_templates")!;
      const result = (await handler({ search: "domain" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].name).toBe("domain-ip");
    });

    it("should respect limit", async () => {
      vi.stubGlobal("fetch", mockFetch([
        { ObjectTemplate: { id: "1", uuid: "t-1", name: "file", description: "File", version: "1", meta_category: "file" } },
        { ObjectTemplate: { id: "2", uuid: "t-2", name: "email", description: "Email", version: "1", meta_category: "misc" } },
        { ObjectTemplate: { id: "3", uuid: "t-3", name: "url", description: "URL", version: "1", meta_category: "network" } },
      ]));

      const handler = handlers.get("misp_list_object_templates")!;
      const result = (await handler({ limit: 2 })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(2);
    });
  });

  describe("misp_get_object_template", () => {
    it("should return template details", async () => {
      vi.stubGlobal("fetch", mockFetch({
        ObjectTemplate: {
          id: "1", uuid: "t-1", name: "file", description: "File object",
          version: "24", meta_category: "file",
          ObjectTemplateElement: [
            { object_relation: "filename", type: "filename", description: "Filename", ui_priority: 1, categories: ["Payload delivery"] },
            { object_relation: "md5", type: "md5", description: "MD5 hash", ui_priority: 2, categories: ["Payload delivery"] },
          ],
        },
      }));

      const handler = handlers.get("misp_get_object_template")!;
      const result = (await handler({ templateId: "1" })) as { content: Array<{ text: string }> };
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("file");
      expect(data.ObjectTemplateElement).toHaveLength(2);
    });
  });

  describe("misp_add_object", () => {
    it("should add an object to an event", async () => {
      vi.stubGlobal("fetch", mockFetch({
        Object: {
          id: "10", name: "file", event_id: "42", meta_category: "file",
          description: "File object", uuid: "obj-10", timestamp: "1717200000",
          distribution: "0",
          Attribute: [
            { type: "filename", object_relation: "filename", value: "malware.exe", id: "100", event_id: "42", category: "Payload delivery", to_ids: true, uuid: "a1", timestamp: "1717200000", distribution: "0", comment: "", deleted: false },
            { type: "md5", object_relation: "md5", value: "abc123", id: "101", event_id: "42", category: "Payload delivery", to_ids: true, uuid: "a2", timestamp: "1717200000", distribution: "0", comment: "", deleted: false },
          ],
        },
      }));

      const handler = handlers.get("misp_add_object")!;
      const result = (await handler({
        eventId: "42",
        templateName: "file",
        attributes: [
          { object_relation: "filename", type: "filename", value: "malware.exe" },
          { object_relation: "md5", type: "md5", value: "abc123" },
        ],
      })) as { content: Array<{ text: string }> };

      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe("10");
      expect(data.name).toBe("file");
      expect(data.attributes).toHaveLength(2);
    });
  });

  describe("misp_delete_object", () => {
    it("should delete an object", async () => {
      vi.stubGlobal("fetch", mockFetch({ message: "Object deleted." }));
      const handler = handlers.get("misp_delete_object")!;
      const result = (await handler({ objectId: "10" })) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain("deleted");
    });
  });
});
