import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetch } from "undici";

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: vi.fn(),
}));
import { MispClient } from "../src/client.js";
import type { MispConfig } from "../src/config.js";

const mockConfig: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-api-key-12345",
  verifySsl: true,
  timeout: 30000,
};

function mockFetch(response: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () =>
      Promise.resolve(
        typeof response === "string" ? response : JSON.stringify(response)
      ),
  });
}

describe("MispClient", () => {
  let client: MispClient;

  beforeEach(() => {
    client = new MispClient(mockConfig);
  });

  describe("searchEvents", () => {
    it("should search events and return parsed results", async () => {
      const mockResponse = {
        response: [
          {
            Event: {
              id: "1",
              info: "Phishing campaign targeting finance sector",
              date: "2024-03-15",
              threat_level_id: "1",
              analysis: "2",
              distribution: "1",
              published: true,
              uuid: "abc-123",
              timestamp: "1710489600",
              publish_timestamp: "1710489600",
              attribute_count: "15",
              Orgc: { id: "1", name: "CERT-EU", uuid: "org-1" },
              Tag: [
                { id: "1", name: "tlp:amber", colour: "#FFC000", exportable: true },
              ],
            },
          },
        ],
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const events = await client.searchEvents({ value: "evil.com" });

      expect(events).toHaveLength(1);
      expect(events[0].info).toBe("Phishing campaign targeting finance sector");
      expect(events[0].Orgc?.name).toBe("CERT-EU");
      expect(events[0].Tag).toHaveLength(1);

      const fetchCall = vi.mocked(fetch).mock.calls[0];
      expect(fetchCall[0]).toBe("https://misp.example.com/events/restSearch");
      const body = JSON.parse(fetchCall[1]?.body as string);
      expect(body.value).toBe("evil.com");
      expect(body.returnFormat).toBe("json");
    });

    it("should return empty array when no events found", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ response: [] }));
      const events = await client.searchEvents({});
      expect(events).toHaveLength(0);
    });

    it("should pass all search parameters correctly", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ response: [] }));
      await client.searchEvents({
        value: "10.0.0.1",
        type: "ip-src",
        category: "Network activity",
        tags: ["tlp:white"],
        org: "CERT-EU",
        dateFrom: "2024-01-01",
        dateTo: "2024-12-31",
        last: "30d",
        published: true,
        limit: 10,
        page: 2,
      });

      const body = JSON.parse(
        vi.mocked(fetch).mock.calls[0][1]?.body as string
      );
      expect(body.value).toBe("10.0.0.1");
      expect(body.type).toBe("ip-src");
      expect(body.category).toBe("Network activity");
      expect(body.tags).toEqual(["tlp:white"]);
      expect(body.org).toBe("CERT-EU");
      expect(body.from).toBe("2024-01-01");
      expect(body.to).toBe("2024-12-31");
      expect(body.last).toBe("30d");
      expect(body.published).toBe(1);
      expect(body.limit).toBe(10);
      expect(body.page).toBe(2);
    });
  });

  describe("getEvent", () => {
    it("should get event details", async () => {
      const mockEvent = {
        Event: {
          id: "42",
          info: "Ransomware incident",
          date: "2024-06-01",
          threat_level_id: "1",
          analysis: "1",
          distribution: "0",
          published: false,
          uuid: "evt-42",
          timestamp: "1717200000",
          publish_timestamp: "0",
          attribute_count: "8",
          Attribute: [
            {
              id: "100",
              event_id: "42",
              type: "sha256",
              category: "Payload delivery",
              value: "abc123def456",
              to_ids: true,
              uuid: "attr-100",
              timestamp: "1717200000",
              distribution: "0",
              comment: "Ransomware payload",
              deleted: false,
            },
          ],
          Object: [],
          Galaxy: [],
          RelatedEvent: [],
          Tag: [{ id: "5", name: "tlp:red", colour: "#CC0033", exportable: true }],
        },
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockEvent));
      const event = await client.getEvent("42");

      expect(event.id).toBe("42");
      expect(event.info).toBe("Ransomware incident");
      expect(event.Attribute).toHaveLength(1);
      expect(event.Attribute![0].value).toBe("abc123def456");

      const fetchCall = vi.mocked(fetch).mock.calls[0];
      expect(fetchCall[0]).toBe("https://misp.example.com/events/view/42");
    });
  });

  describe("createEvent", () => {
    it("should create an event", async () => {
      const mockResponse = {
        Event: {
          id: "99",
          info: "New incident report",
          date: "2024-07-01",
          threat_level_id: "2",
          analysis: "0",
          distribution: "0",
          published: false,
          uuid: "new-evt-99",
          timestamp: "1719792000",
          publish_timestamp: "0",
          attribute_count: "0",
          Tag: [],
        },
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const event = await client.createEvent({
        info: "New incident report",
        distribution: 0,
        threat_level_id: 2,
        analysis: 0,
      });

      expect(event.id).toBe("99");
      expect(event.info).toBe("New incident report");

      const body = JSON.parse(
        vi.mocked(fetch).mock.calls[0][1]?.body as string
      );
      expect(body.Event.info).toBe("New incident report");
      expect(body.Event.distribution).toBe(0);
      expect(body.Event.threat_level_id).toBe(2);
    });
  });

  describe("updateEvent", () => {
    it("should update event metadata", async () => {
      const mockResponse = {
        Event: {
          id: "42",
          info: "Updated incident",
          threat_level_id: "1",
          analysis: "2",
          published: true,
        },
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const event = await client.updateEvent("42", {
        info: "Updated incident",
        threat_level_id: 1,
        analysis: 2,
      });

      expect(event.info).toBe("Updated incident");
      const fetchCall = vi.mocked(fetch).mock.calls[0];
      expect(fetchCall[0]).toBe("https://misp.example.com/events/edit/42");
    });
  });

  describe("publishEvent", () => {
    it("should publish an event", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Event published." }));
      const result = await client.publishEvent("42");
      expect(result.message).toBe("Event published.");
    });
  });

  describe("searchAttributes", () => {
    it("should search attributes with filters", async () => {
      const mockResponse = {
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
              comment: "C2 server",
              deleted: false,
              Event: { info: "Ransomware incident" },
            },
          ],
        },
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const attrs = await client.searchAttributes({
        value: "10.0.0.1",
        type: "ip-src",
        to_ids: true,
        includeCorrelations: true,
      });

      expect(attrs).toHaveLength(1);
      expect(attrs[0].value).toBe("10.0.0.1");
      expect(attrs[0].type).toBe("ip-src");

      const body = JSON.parse(
        vi.mocked(fetch).mock.calls[0][1]?.body as string
      );
      expect(body.value).toBe("10.0.0.1");
      expect(body.type).toBe("ip-src");
      expect(body.to_ids).toBe(1);
      expect(body.includeCorrelations).toBe(1);
    });
  });

  describe("addAttribute", () => {
    it("should add an attribute to an event", async () => {
      const mockResponse = {
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
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const attr = await client.addAttribute("42", {
        type: "domain",
        value: "evil.com",
        comment: "C2 domain",
      });

      expect(attr.id).toBe("300");
      expect(attr.value).toBe("evil.com");

      const fetchCall = vi.mocked(fetch).mock.calls[0];
      expect(fetchCall[0]).toBe(
        "https://misp.example.com/attributes/add/42"
      );
    });
  });

  describe("deleteAttribute", () => {
    it("should soft delete an attribute", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Attribute deleted." })
      );
      const result = await client.deleteAttribute("300");
      expect(result.message).toBe("Attribute deleted.");
    });

    it("should hard delete an attribute", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Attribute permanently deleted." })
      );
      const result = await client.deleteAttribute("300", true);

      const body = JSON.parse(
        vi.mocked(fetch).mock.calls[0][1]?.body as string
      );
      expect(body.hard).toBe(1);
    });
  });

  describe("describeTypes", () => {
    it("should return type information", async () => {
      const mockResponse = {
        result: {
          sane_defaults: {
            "ip-src": { default_category: "Network activity", to_ids: 1 },
            domain: { default_category: "Network activity", to_ids: 1 },
          },
          types: ["ip-src", "ip-dst", "domain", "md5", "sha256"],
          categories: ["Network activity", "Payload delivery"],
          category_type_mappings: {
            "Network activity": ["ip-src", "ip-dst", "domain"],
            "Payload delivery": ["md5", "sha256"],
          },
        },
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const types = await client.describeTypes();

      expect(types.types).toContain("ip-src");
      expect(types.categories).toContain("Network activity");
    });
  });

  describe("listTags", () => {
    it("should list all tags", async () => {
      const mockResponse = {
        Tag: [
          { id: "1", name: "tlp:white", colour: "#FFFFFF", exportable: true },
          { id: "2", name: "tlp:green", colour: "#339900", exportable: true },
        ],
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const tags = await client.listTags();
      expect(tags).toHaveLength(2);
      expect(tags[0].name).toBe("tlp:white");
    });

    it("should search tags by name", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ Tag: [] }));
      await client.listTags("mitre");

      const fetchCall = vi.mocked(fetch).mock.calls[0];
      expect(fetchCall[0]).toBe(
        "https://misp.example.com/tags/search/mitre"
      );
    });
  });

  describe("addSighting", () => {
    it("should add a sighting by attribute ID", async () => {
      const mockResponse = {
        Sighting: {
          id: "10",
          attribute_id: "200",
          event_id: "42",
          org_id: "1",
          date_sighting: "1717200000",
          source: "IDS-sensor-1",
          type: "0",
        },
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const sighting = await client.addSighting({
        attributeId: "200",
        type: 0,
        source: "IDS-sensor-1",
      });

      expect(sighting.id).toBe("10");
      expect(sighting.attribute_id).toBe("200");

      const fetchCall = vi.mocked(fetch).mock.calls[0];
      expect(fetchCall[0]).toBe(
        "https://misp.example.com/sightings/add/200"
      );
    });

    it("should add a sighting by value", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({
          Sighting: {
            id: "11",
            attribute_id: "201",
            event_id: "42",
            org_id: "1",
            date_sighting: "1717200000",
            source: "",
            type: "1",
          },
        })
      );

      const sighting = await client.addSighting({
        value: "evil.com",
        type: 1,
      });

      expect(sighting.id).toBe("11");
      const fetchCall = vi.mocked(fetch).mock.calls[0];
      expect(fetchCall[0]).toBe("https://misp.example.com/sightings/add");
    });
  });

  describe("checkWarninglists", () => {
    it("should check a value against warninglists", async () => {
      const mockResponse = {
        "8.8.8.8": [
          {
            id: "1",
            name: "List of known Google resolvers",
            type: "cidr",
            description: "Google DNS resolvers",
            category: "Known benign",
            warninglist_entry_count: "4",
          },
        ],
      };

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const result = await client.checkWarninglists("8.8.8.8");

      expect(result["8.8.8.8"]).toHaveLength(1);
      expect(result["8.8.8.8"][0].name).toBe(
        "List of known Google resolvers"
      );
    });
  });

  describe("exportEvents", () => {
    it("should export in CSV format", async () => {
      const csvOutput = "uuid,event_id,category,type,value\nabc,42,Network activity,ip-src,10.0.0.1";
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(csvOutput));
      const result = await client.exportEvents({ format: "csv" });
      expect(result).toContain("ip-src");
    });

    it("should reject unsupported formats", async () => {
      await expect(
        client.exportEvents({ format: "invalid" })
      ).rejects.toThrow("Unsupported export format");
    });
  });

  describe("exportHashes", () => {
    it("should export SHA256 hashes", async () => {
      const hashOutput = "abc123def456\n789ghi012jkl";
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(hashOutput));
      const result = await client.exportHashes({ format: "sha256" });
      expect(result).toContain("abc123def456");
    });

    it("should reject unsupported hash formats", async () => {
      await expect(
        client.exportHashes({ format: "sha512" })
      ).rejects.toThrow("Unsupported hash format");
    });
  });

  describe("listTaxonomies", () => {
    it("should return taxonomy list", async () => {
      const mockResponse = [
        {
          Taxonomy: {
            namespace: "tlp",
            description: "Traffic Light Protocol",
            version: "3",
            enabled: true,
          },
        },
        {
          Taxonomy: {
            namespace: "mitre-attack-pattern",
            description: "MITRE ATT&CK Patterns",
            version: "8",
            enabled: true,
          },
        },
      ];

      vi.mocked(fetch).mockReset().mockImplementation(mockFetch(mockResponse));
      const taxonomies = await client.listTaxonomies();

      expect(taxonomies).toHaveLength(2);
      expect(taxonomies[0].namespace).toBe("tlp");
    });
  });

  describe("error handling", () => {
    it("should handle 401 unauthorized", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Authentication failed" }, 401)
      );
      await expect(client.searchEvents({})).rejects.toThrow(
        "Invalid API key or unauthorized"
      );
    });

    it("should handle 403 forbidden", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Forbidden" }, 403)
      );
      await expect(client.createEvent({
        info: "Test",
        distribution: 0,
        threat_level_id: 2,
        analysis: 0,
      })).rejects.toThrow("Insufficient permissions");
    });

    it("should handle 404 not found", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Event not found" }, 404)
      );
      await expect(client.getEvent("99999")).rejects.toThrow(
        "Resource not found"
      );
    });

    it("should handle 500 server error", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Internal error" }, 500)
      );
      await expect(client.searchEvents({})).rejects.toThrow("HTTP 500");
    });

    it("should handle network errors", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(vi.fn().mockRejectedValue(new Error("ECONNREFUSED"))
      );
      await expect(client.searchEvents({})).rejects.toThrow(
        "MISP API request failed: ECONNREFUSED"
      );
    });

    it("should surface the cause chain behind generic fetch failures", async () => {
      const tlsError = new Error("self-signed certificate") as NodeJS.ErrnoException;
      tlsError.code = "DEPTH_ZERO_SELF_SIGNED_CERT";
      vi.mocked(fetch).mockReset().mockImplementation(
        vi.fn().mockRejectedValue(new Error("fetch failed", { cause: tlsError }))
      );
      await expect(client.searchEvents({})).rejects.toThrow(
        /fetch failed -> self-signed certificate.*MISP_VERIFY_SSL=false/
      );
    });

    it("should hint at connectivity for unreachable hosts", async () => {
      const connError = new Error("connect ECONNREFUSED 192.0.2.1:443") as NodeJS.ErrnoException;
      connError.code = "ECONNREFUSED";
      vi.mocked(fetch).mockReset().mockImplementation(
        vi.fn().mockRejectedValue(new Error("fetch failed", { cause: connError }))
      );
      await expect(client.searchEvents({})).rejects.toThrow(
        /ECONNREFUSED.*not reachable from this machine/
      );
    });

    it("should include detail in error messages", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ message: "Attribute validation failed: value already exists" }, 403)
      );
      await expect(
        client.addAttribute("42", { type: "domain", value: "evil.com" })
      ).rejects.toThrow("value already exists");
    });
  });

  describe("authorization header", () => {
    it("should send API key in Authorization header", async () => {
      vi.mocked(fetch).mockReset().mockImplementation(mockFetch({ response: [] }));
      await client.searchEvents({});

      const headers = vi.mocked(fetch).mock.calls[0][1]?.headers as Record<
        string,
        string
      >;
      expect(headers.Authorization).toBe("test-api-key-12345");
      expect(headers["Content-Type"]).toBe("application/json");
      expect(headers.Accept).toBe("application/json");
    });
  });
});
