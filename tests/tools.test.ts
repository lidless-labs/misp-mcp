import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetch } from "undici";

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: vi.fn(),
}));
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MispClient } from "../src/client.js";
import { registerEventTools } from "../src/tools/events.js";
import { registerAttributeTools } from "../src/tools/attributes.js";
import { registerCorrelationTools } from "../src/tools/correlation.js";
import { registerTagTools } from "../src/tools/tags.js";
import { registerExportTools } from "../src/tools/exports.js";
import { registerSightingTools } from "../src/tools/sightings.js";
import { registerWarninglistTools } from "../src/tools/warninglists.js";
import type { MispConfig } from "../src/config.js";

const mockConfig: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-key",
  verifySsl: true,
  timeout: 30000,
};

// Helper to extract the tool handler from McpServer registration
function createTestHarness() {
  const handlers = new Map<string, (params: Record<string, unknown>) => Promise<unknown>>();

  const mockServer = {
    tool: vi.fn(
      (
        name: string,
        _descriptionOrSchema: unknown,
        schemaOrHandler: unknown,
        handler?: unknown
      ) => {
        // Handle both 3-arg and 4-arg overloads
        const actualHandler = (handler || schemaOrHandler) as (
          params: Record<string, unknown>
        ) => Promise<unknown>;
        handlers.set(name, actualHandler);
      }
    ),
    resource: vi.fn(),
    prompt: vi.fn(),
  } as unknown as McpServer;

  return { mockServer, handlers };
}

function mockFetchResponse(response: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () =>
      Promise.resolve(
        typeof response === "string" ? response : JSON.stringify(response)
      ),
  });
}

describe("Event Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;
  let client: MispClient;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    client = new MispClient(mockConfig);
    registerEventTools(harness.mockServer, client);
  });

  describe("misp_search_events", () => {
    it("should return formatted event results", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          response: [
            {
              Event: {
                id: "1",
                info: "APT28 campaign",
                date: "2024-03-15",
                threat_level_id: "1",
                analysis: "2",
                distribution: "1",
                published: true,
                uuid: "abc",
                timestamp: "1710489600",
                publish_timestamp: "1710489600",
                attribute_count: "25",
                Orgc: { id: "1", name: "CERT-EU", uuid: "org-1" },
                Tag: [{ id: "1", name: "tlp:amber", colour: "#FFC000", exportable: true }],
              },
            },
          ],
        })
      );

      const handler = handlers.get("misp_search_events")!;
      const result = (await handler({ value: "evil.com" })) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].id).toBe("1");
      expect(data[0].info).toBe("APT28 campaign");
      expect(data[0].threat_level).toBe("High");
      expect(data[0].org).toBe("CERT-EU");
      expect(data[0].tags).toContain("tlp:amber");
    });

    it("should handle no results", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ response: [] }));
      const handler = handlers.get("misp_search_events")!;
      const result = (await handler({})) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("No events found");
    });

    it("should handle errors gracefully", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(vi.fn().mockRejectedValue(new Error("Connection refused"))
      );
      const handler = handlers.get("misp_search_events")!;
      const result = (await handler({})) as {
        content: Array<{ type: string; text: string }>;
        isError: boolean;
      };
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error searching events");
    });
  });

  describe("misp_get_event", () => {
    it("should return full event details", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          Event: {
            id: "42",
            uuid: "evt-42",
            info: "Ransomware incident",
            date: "2024-06-01",
            threat_level_id: "1",
            analysis: "1",
            distribution: "0",
            published: false,
            timestamp: "1717200000",
            publish_timestamp: "0",
            attribute_count: "3",
            Orgc: { id: "1", name: "SOC Team", uuid: "org-1" },
            Tag: [{ id: "1", name: "tlp:red", colour: "#CC0033", exportable: true }],
            Attribute: [
              {
                id: "100",
                event_id: "42",
                type: "sha256",
                category: "Payload delivery",
                value: "abc123",
                to_ids: true,
                uuid: "attr-100",
                timestamp: "1717200000",
                distribution: "0",
                comment: "Payload hash",
                deleted: false,
              },
            ],
            Object: [],
            Galaxy: [
              {
                id: "1",
                uuid: "gal-1",
                name: "MITRE ATT&CK",
                type: "mitre-attack-pattern",
                description: "ATT&CK patterns",
                GalaxyCluster: [
                  {
                    id: "1",
                    uuid: "cl-1",
                    type: "mitre-attack-pattern",
                    value: "T1486 - Data Encrypted for Impact",
                    tag_name: "misp-galaxy:mitre-attack-pattern=\"T1486\"",
                    description: "Ransomware encryption",
                  },
                ],
              },
            ],
            RelatedEvent: [
              {
                Event: { id: "41", info: "Previous ransomware wave", date: "2024-05-20" },
              },
            ],
          },
        })
      );

      const handler = handlers.get("misp_get_event")!;
      const result = (await handler({ eventId: "42" })) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe("42");
      expect(data.threat_level).toBe("High");
      expect(data.analysis).toBe("Ongoing");
      expect(data.distribution).toBe("Organization");
      expect(data.attributes).toHaveLength(1);
      expect(data.attributes[0].value).toBe("abc123");
      expect(data.galaxies).toHaveLength(1);
      expect(data.galaxies[0].clusters).toContain("T1486 - Data Encrypted for Impact");
      expect(data.related_events).toHaveLength(1);
    });
  });

  describe("misp_create_event", () => {
    it("should create an event and return its details", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          Event: {
            id: "99",
            uuid: "new-99",
            info: "New phishing campaign",
            date: "2024-07-01",
            threat_level_id: "2",
            analysis: "0",
            distribution: "0",
            published: false,
            timestamp: "1719792000",
            publish_timestamp: "0",
            attribute_count: "0",
            Tag: [],
          },
        })
      );

      const handler = handlers.get("misp_create_event")!;
      const result = (await handler({
        info: "New phishing campaign",
        distribution: 0,
        threatLevel: 2,
        analysis: 0,
      })) as { content: Array<{ type: string; text: string }> };

      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe("99");
      expect(data.info).toBe("New phishing campaign");
    });
  });

  describe("misp_publish_event", () => {
    it("should publish an event", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ message: "Event published." })
      );
      const handler = handlers.get("misp_publish_event")!;
      const result = (await handler({ eventId: "42", confirm: true })) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("published");
    });

    it("should refuse to publish without confirmation", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ message: "Event published." })
      );
      const handler = handlers.get("misp_publish_event")!;
      const result = (await handler({ eventId: "42" })) as {
        content: Array<{ type: string; text: string }>;
        isError: boolean;
      };
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Refused");
    });
  });

  describe("misp_tag_event", () => {
    it("should add a tag", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ saved: true }));
      const handler = handlers.get("misp_tag_event")!;
      const result = (await handler({
        eventId: "42",
        tag: "tlp:amber",
      })) as { content: Array<{ type: string; text: string }> };
      expect(result.content[0].text).toContain("added");
    });

    it("should remove a tag", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ saved: true }));
      const handler = handlers.get("misp_tag_event")!;
      const result = (await handler({
        eventId: "42",
        tag: "tlp:white",
        remove: true,
        confirm: true,
      })) as { content: Array<{ type: string; text: string }> };
      expect(result.content[0].text).toContain("removed");
    });

    it("should refuse to remove a tag without confirmation", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ saved: true }));
      const handler = handlers.get("misp_tag_event")!;
      const result = (await handler({
        eventId: "42",
        tag: "tlp:white",
        remove: true,
      })) as { content: Array<{ type: string; text: string }>; isError: boolean };
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Refused");
    });
  });
});

describe("Attribute Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;
  let client: MispClient;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    client = new MispClient(mockConfig);
    registerAttributeTools(harness.mockServer, client);
  });

  describe("misp_search_attributes", () => {
    it("should return formatted attribute results", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          response: {
            Attribute: [
              {
                id: "200",
                event_id: "42",
                type: "ip-src",
                category: "Network activity",
                value: "10.0.0.1",
                to_ids: true,
                uuid: "attr-200",
                timestamp: "1717200000",
                distribution: "0",
                comment: "C2 IP",
                deleted: false,
                Event: { info: "Ransomware incident" },
                Tag: [{ id: "1", name: "tlp:red", colour: "#CC0033", exportable: true }],
              },
            ],
          },
        })
      );

      const handler = handlers.get("misp_search_attributes")!;
      const result = (await handler({ value: "10.0.0.1" })) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].value).toBe("10.0.0.1");
      expect(data[0].type).toBe("ip-src");
      expect(data[0].event_info).toBe("Ransomware incident");
      expect(data[0].tags).toContain("tlp:red");
    });
  });

  describe("misp_add_attribute", () => {
    it("should add an attribute and return details", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          Attribute: {
            id: "300",
            event_id: "42",
            type: "domain",
            category: "Network activity",
            value: "evil.com",
            to_ids: true,
            uuid: "attr-300",
            timestamp: "1717200000",
            distribution: "0",
            comment: "C2 domain",
            deleted: false,
          },
        })
      );

      const handler = handlers.get("misp_add_attribute")!;
      const result = (await handler({
        eventId: "42",
        type: "domain",
        value: "evil.com",
        comment: "C2 domain",
      })) as { content: Array<{ type: string; text: string }> };

      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe("300");
      expect(data.value).toBe("evil.com");
      expect(data.type).toBe("domain");
    });
  });

  describe("misp_add_attributes_bulk", () => {
    it("should add multiple attributes and report results", async () => {
      let callCount = 0;
      vi.mocked(fetch).mockReset().mockImplementation(vi.fn().mockImplementation(() => {
          callCount++;
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () =>
              Promise.resolve(
                JSON.stringify({
                  Attribute: {
                    id: String(300 + callCount),
                    event_id: "42",
                    type: "ip-src",
                    category: "Network activity",
                    value: `10.0.0.${callCount}`,
                    to_ids: true,
                    uuid: `attr-${300 + callCount}`,
                    timestamp: "1717200000",
                    distribution: "0",
                    comment: "",
                    deleted: false,
                  },
                })
              ),
          });
        })
      );

      const handler = handlers.get("misp_add_attributes_bulk")!;
      const result = (await handler({
        eventId: "42",
        attributes: [
          { type: "ip-src", value: "10.0.0.1" },
          { type: "ip-src", value: "10.0.0.2" },
          { type: "ip-src", value: "10.0.0.3" },
        ],
      })) as { content: Array<{ type: string; text: string }> };

      const data = JSON.parse(result.content[0].text);
      expect(data.total).toBe(3);
      expect(data.succeeded).toBe(3);
      expect(data.failed).toBe(0);
    });

    it("should handle partial failures in bulk add", async () => {
      let callCount = 0;
      vi.mocked(fetch).mockReset().mockImplementation(vi.fn().mockImplementation(() => {
          callCount++;
          if (callCount === 2) {
            return Promise.resolve({
              ok: false,
              status: 403,
              text: () => Promise.resolve(JSON.stringify({ message: "Duplicate value" })),
            });
          }
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () =>
              Promise.resolve(
                JSON.stringify({
                  Attribute: {
                    id: String(300 + callCount),
                    event_id: "42",
                    type: "ip-src",
                    category: "Network activity",
                    value: `10.0.0.${callCount}`,
                    to_ids: true,
                  },
                })
              ),
          });
        })
      );

      const handler = handlers.get("misp_add_attributes_bulk")!;
      const result = (await handler({
        eventId: "42",
        attributes: [
          { type: "ip-src", value: "10.0.0.1" },
          { type: "ip-src", value: "10.0.0.2" },
          { type: "ip-src", value: "10.0.0.3" },
        ],
      })) as { content: Array<{ type: string; text: string }> };

      const data = JSON.parse(result.content[0].text);
      expect(data.total).toBe(3);
      expect(data.succeeded).toBe(2);
      expect(data.failed).toBe(1);
    });
  });

  describe("misp_delete_attribute", () => {
    it("should delete an attribute", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ message: "Attribute deleted." })
      );
      const handler = handlers.get("misp_delete_attribute")!;
      const result = (await handler({ attributeId: "300", confirm: true })) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("deleted");
    });

    it("should refuse soft delete without confirmation", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ message: "Attribute deleted." })
      );
      const handler = handlers.get("misp_delete_attribute")!;
      const result = (await handler({ attributeId: "300" })) as {
        content: Array<{ type: string; text: string }>;
        isError: boolean;
      };
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Refused");
    });

    it("should refuse hard delete without confirmHard", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ message: "Attribute deleted." })
      );
      const handler = handlers.get("misp_delete_attribute")!;
      const result = (await handler({
        attributeId: "300",
        hard: true,
        confirm: true,
      })) as {
        content: Array<{ type: string; text: string }>;
        isError: boolean;
      };
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("PERMANENT");
    });
  });
});

describe("Correlation Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerCorrelationTools(harness.mockServer, client);
  });

  describe("misp_correlate", () => {
    it("should aggregate correlations by event", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          response: {
            Attribute: [
              {
                id: "200",
                event_id: "42",
                type: "ip-src",
                category: "Network activity",
                value: "10.0.0.1",
                to_ids: true,
                uuid: "attr-200",
                timestamp: "1717200000",
                distribution: "0",
                comment: "",
                deleted: false,
                Event: { info: "Ransomware incident" },
                RelatedAttribute: [
                  { id: "300", value: "10.0.0.1", type: "ip-dst", event_id: "43" },
                ],
              },
              {
                id: "400",
                event_id: "43",
                type: "ip-dst",
                category: "Network activity",
                value: "10.0.0.1",
                to_ids: true,
                uuid: "attr-400",
                timestamp: "1717200000",
                distribution: "0",
                comment: "",
                deleted: false,
                Event: { info: "APT campaign" },
              },
            ],
          },
        })
      );

      const handler = handlers.get("misp_correlate")!;
      const result = (await handler({ value: "10.0.0.1" })) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data.searched_value).toBe("10.0.0.1");
      expect(data.total_events).toBe(2);
      expect(data.total_attributes).toBe(2);
      expect(data.correlations).toHaveLength(1);
    });

    it("should handle no correlations found", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ response: { Attribute: [] } })
      );
      const handler = handlers.get("misp_correlate")!;
      const result = (await handler({ value: "not-found.com" })) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("No results found");
    });
  });

  describe("misp_describe_types", () => {
    it("should return type information", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          result: {
            sane_defaults: {},
            types: ["ip-src", "domain"],
            categories: ["Network activity"],
            category_type_mappings: {},
          },
        })
      );
      const handler = handlers.get("misp_describe_types")!;
      const result = (await handler({})) as {
        content: Array<{ type: string; text: string }>;
      };
      const data = JSON.parse(result.content[0].text);
      expect(data.types).toContain("ip-src");
    });
  });
});

describe("Tag Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerTagTools(harness.mockServer, client);
  });

  describe("misp_list_tags", () => {
    it("should list tags with stats", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          Tag: [
            { id: "1", name: "tlp:white", colour: "#FFFFFF", exportable: true, event_count: "50", attribute_count: "200" },
            { id: "2", name: "tlp:green", colour: "#339900", exportable: true, event_count: "30", attribute_count: "120" },
          ],
        })
      );

      const handler = handlers.get("misp_list_tags")!;
      const result = (await handler({})) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(2);
      expect(data[0].name).toBe("tlp:white");
    });

    it("should respect limit parameter", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          Tag: [
            { id: "1", name: "tag-1", colour: "#FFF", exportable: true },
            { id: "2", name: "tag-2", colour: "#FFF", exportable: true },
            { id: "3", name: "tag-3", colour: "#FFF", exportable: true },
          ],
        })
      );

      const handler = handlers.get("misp_list_tags")!;
      const result = (await handler({ limit: 2 })) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(2);
    });
  });

  describe("misp_search_by_tag", () => {
    it("should search events by tag", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          response: [
            {
              Event: {
                id: "1",
                info: "Test event",
                date: "2024-01-01",
                threat_level_id: "2",
                analysis: "0",
                distribution: "1",
                published: true,
                uuid: "abc",
                timestamp: "1704067200",
                publish_timestamp: "1704067200",
                attribute_count: "5",
                Orgc: { id: "1", name: "SOC", uuid: "org-1" },
                Tag: [{ id: "1", name: "tlp:amber", colour: "#FFC000", exportable: true }],
              },
            },
          ],
        })
      );

      const handler = handlers.get("misp_search_by_tag")!;
      const result = (await handler({ tag: "tlp:amber" })) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data).toHaveLength(1);
      expect(data[0].tags).toContain("tlp:amber");
    });
  });
});

describe("Export Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerExportTools(harness.mockServer, client);
  });

  describe("misp_export_iocs", () => {
    it("should export IOCs in CSV format", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse("uuid,event_id,type,value\nabc,42,ip-src,10.0.0.1")
      );
      const handler = handlers.get("misp_export_iocs")!;
      const result = (await handler({ format: "csv" })) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("ip-src");
    });

    it("should handle empty exports", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse(""));
      const handler = handlers.get("misp_export_iocs")!;
      const result = (await handler({ format: "csv" })) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("No IOCs found");
    });
  });

  describe("misp_export_hashes", () => {
    it("should export SHA256 hashes", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse("abc123def456\n789ghi012jkl")
      );
      const handler = handlers.get("misp_export_hashes")!;
      const result = (await handler({ format: "sha256" })) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("abc123def456");
    });
  });
});

describe("Sighting Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerSightingTools(harness.mockServer, client);
  });

  describe("misp_add_sighting", () => {
    it("should add a sighting", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          Sighting: {
            id: "10",
            attribute_id: "200",
            event_id: "42",
            org_id: "1",
            date_sighting: "1717200000",
            source: "IDS",
            type: "0",
          },
        })
      );

      const handler = handlers.get("misp_add_sighting")!;
      const result = (await handler({
        attributeId: "200",
        type: 0,
        source: "IDS",
      })) as { content: Array<{ type: string; text: string }> };

      const data = JSON.parse(result.content[0].text);
      expect(data.type).toBe("Sighting");
      expect(data.attribute_id).toBe("200");
    });

    it("should require either attributeId or value", async () => {
      const handler = handlers.get("misp_add_sighting")!;
      const result = (await handler({ type: 0 })) as {
        content: Array<{ type: string; text: string }>;
        isError: boolean;
      };
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Either attributeId or value");
    });
  });
});

describe("Warninglist Tools", () => {
  let handlers: Map<string, (params: Record<string, unknown>) => Promise<unknown>>;

  beforeEach(() => {
    const harness = createTestHarness();
    handlers = harness.handlers;
    const client = new MispClient(mockConfig);
    registerWarninglistTools(harness.mockServer, client);
  });

  describe("misp_check_warninglists", () => {
    it("should report matches on warninglists", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({
          "8.8.8.8": [
            {
              id: "1",
              name: "List of known Google resolvers",
              type: "cidr",
              description: "Google DNS",
              category: "Known benign",
              warninglist_entry_count: "4",
            },
          ],
        })
      );

      const handler = handlers.get("misp_check_warninglists")!;
      const result = (await handler({ value: "8.8.8.8" })) as {
        content: Array<{ type: string; text: string }>;
      };

      const data = JSON.parse(result.content[0].text);
      expect(data.on_warninglists).toBe(true);
      expect(data.match_count).toBe(1);
      expect(data.warninglists[0].name).toBe("List of known Google resolvers");
    });

    it("should report no matches", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetchResponse({ "evil.com": [] })
      );

      const handler = handlers.get("misp_check_warninglists")!;
      const result = (await handler({ value: "evil.com" })) as {
        content: Array<{ type: string; text: string }>;
      };
      expect(result.content[0].text).toContain("does not appear on any warninglists");
    });
  });
});
