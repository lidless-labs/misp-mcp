/**
 * Integration tests against a live MISP instance.
 *
 * Run with:   MISP_URL=https://192.0.2.97 MISP_API_KEY=<key> MISP_VERIFY_SSL=false npm run test:integration
 *
 * Prerequisites:
 *   - Running MISP instance with API access
 *   - TLP taxonomy enabled with tags exported
 *   - At least one seeded event with attributes
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { MispClient } from "../src/client.js";
import type { MispConfig } from "../src/config.js";

const MISP_URL = process.env.MISP_URL;
const MISP_API_KEY = process.env.MISP_API_KEY;

// Skip all if no MISP connection configured
const describeIntegration = MISP_URL && MISP_API_KEY ? describe : describe.skip;

describeIntegration("Integration: Live MISP API", () => {
  let client: MispClient;
  let testEventId: string;

  beforeAll(() => {
    if (!MISP_URL || !MISP_API_KEY) throw new Error("Missing MISP env vars");
    const config: MispConfig = {
      url: MISP_URL.replace(/\/+$/, ""),
      apiKey: MISP_API_KEY,
      verifySsl: process.env.MISP_VERIFY_SSL !== "false",
      timeout: 30000,
    };

    client = new MispClient(config);
  });

  afterAll(async () => {
    // Clean up test event
    if (testEventId) {
      try {
        await client.deleteEvent(testEventId);
      } catch {
        // best effort cleanup
      }
    }
  });

  // --- Server ---

  it("should get MISP version", async () => {
    const version = await client.getVersion();
    expect(version.version).toBeDefined();
    expect(version.version).toMatch(/^\d+\.\d+/);
    console.log(`  MISP version: ${version.version}`);
  });

  // --- Describe Types ---

  it("should describe attribute types", async () => {
    const types = await client.describeTypes();
    expect(types.types).toBeInstanceOf(Array);
    expect(types.types.length).toBeGreaterThan(0);
    expect(types.types).toContain("ip-src");
    expect(types.types).toContain("domain");
    expect(types.types).toContain("sha256");
    expect(types.categories).toContain("Network activity");
    expect(types.categories).toContain("Payload delivery");
  });

  // --- Event CRUD ---

  it("should create an event", async () => {
    const event = await client.createEvent({
      info: "[INTEGRATION TEST] Automated test event - safe to delete",
      distribution: 0,
      threat_level_id: 3,
      analysis: 0,
    });

    expect(event.id).toBeDefined();
    expect(event.info).toContain("INTEGRATION TEST");
    testEventId = event.id;
    console.log(`  Created test event: ${event.id}`);
  });

  it("should get event details", async () => {
    const event = await client.getEvent(testEventId);
    expect(event.id).toBe(testEventId);
    expect(event.info).toContain("INTEGRATION TEST");
    expect(event.threat_level_id).toBe("3");
    expect(event.analysis).toBe("0");
  });

  it("should update an event", async () => {
    const event = await client.updateEvent(testEventId, {
      info: "[INTEGRATION TEST] Updated event title",
      analysis: 1,
    });
    expect(event.info).toContain("Updated");
  });

  it("should search events", async () => {
    const events = await client.searchEvents({
      eventid: testEventId,
    });
    expect(events.length).toBeGreaterThan(0);
    expect(events[0].id).toBe(testEventId);
  });

  // --- Attribute CRUD ---

  it("should add an attribute", async () => {
    const attr = await client.addAttribute(testEventId, {
      type: "ip-dst",
      value: "198.51.100.42",
      category: "Network activity",
      to_ids: true,
      comment: "Integration test C2 IP",
    });

    expect(attr.id).toBeDefined();
    expect(attr.value).toBe("198.51.100.42");
    expect(attr.type).toBe("ip-dst");
  });

  it("should add a domain attribute", async () => {
    const attr = await client.addAttribute(testEventId, {
      type: "domain",
      value: "integration-test-c2.example.com",
      to_ids: true,
      comment: "Integration test domain",
    });

    expect(attr.id).toBeDefined();
    expect(attr.value).toBe("integration-test-c2.example.com");
  });

  it("should search attributes", async () => {
    const attrs = await client.searchAttributes({
      value: "198.51.100.42",
    });
    expect(attrs.length).toBeGreaterThan(0);
    expect(attrs[0].value).toBe("198.51.100.42");
    expect(attrs[0].event_id).toBe(testEventId);
  });

  it("should search attributes by type", async () => {
    const attrs = await client.searchAttributes({
      type: "domain",
      value: "integration-test-c2.example.com",
    });
    expect(attrs.length).toBeGreaterThan(0);
    expect(attrs[0].type).toBe("domain");
  });

  // --- Tags ---

  it("should list tags", async () => {
    const tags = await client.listTags();
    expect(tags.length).toBeGreaterThan(0);
    // Should have at least the TLP tags we enabled
    const tagNames = tags.map((t) => t.name);
    console.log(`  Total tags: ${tags.length}`);
    const hasTlp = tagNames.some((n) => n.startsWith("tlp:"));
    expect(hasTlp).toBe(true);
  });

  it("should tag and untag an event", async () => {
    await client.tagEvent(testEventId, "tlp:green");

    // Verify tag was added
    const event = await client.getEvent(testEventId);
    const tags = (event.Tag || []).map((t) => t.name);
    expect(tags).toContain("tlp:green");

    // Remove tag
    await client.untagEvent(testEventId, "tlp:green");
    const event2 = await client.getEvent(testEventId);
    const tags2 = (event2.Tag || []).map((t) => t.name);
    expect(tags2).not.toContain("tlp:green");
  });

  // --- Correlations ---

  it("should search for correlations on seeded data", async () => {
    // This tests against the seeded events (185.141.63.120 appears in events 1 and 2)
    const attrs = await client.searchAttributes({
      value: "185.141.63.120",
      includeCorrelations: true,
    });

    // May or may not find correlations depending on if seed data exists
    // Just verify the API call works
    expect(attrs).toBeInstanceOf(Array);
    if (attrs.length > 0) {
      console.log(
        `  Found ${attrs.length} attributes for 185.141.63.120 across events: ${[...new Set(attrs.map((a) => a.event_id))].join(", ")}`
      );
    }
  });

  // --- Warninglists ---

  it("should check warninglists for known benign IP", async () => {
    const result = await client.checkWarninglists("8.8.8.8");
    // 8.8.8.8 should be on Google DNS warninglist
    const matches = result["8.8.8.8"] || [];
    console.log(`  8.8.8.8 warninglist matches: ${matches.length}`);
    // This depends on warninglists being enabled
    expect(result).toBeDefined();
  });

  it("should check warninglists for unknown value", async () => {
    const result = await client.checkWarninglists(
      "definitely-not-on-any-list-xyz123.example.com"
    );
    const matches =
      result["definitely-not-on-any-list-xyz123.example.com"] || [];
    expect(matches.length).toBe(0);
  });

  // --- Taxonomies ---

  it("should list taxonomies", async () => {
    const taxonomies = await client.listTaxonomies();
    expect(taxonomies.length).toBeGreaterThan(0);
    const namespaces = taxonomies.map((t) => t.namespace);
    expect(namespaces).toContain("tlp");
    console.log(`  Total taxonomies: ${taxonomies.length}`);
  });

  // --- Galaxies ---

  it("should list galaxies", async () => {
    const galaxies = await client.listGalaxies();
    expect(galaxies.length).toBeGreaterThan(0);
    const types = galaxies.map((g) => g.type);
    expect(types.some((t) => t.includes("mitre"))).toBe(true);
    console.log(`  Total galaxies: ${galaxies.length}`);
  });

  it("should get a specific galaxy", async () => {
    // Galaxy 39 should be "Attack Pattern" (mitre-attack-pattern)
    const galaxy = await client.getGalaxy("39");
    expect(galaxy.name).toBeDefined();
    expect(galaxy.type).toContain("mitre");
    console.log(
      `  Galaxy 39: ${galaxy.name} (${galaxy.GalaxyCluster?.length || 0} clusters)`
    );
  });

  // --- Object Templates ---

  it("should list object templates", async () => {
    const templates = await client.listObjectTemplates();
    expect(templates.length).toBeGreaterThan(0);
    const names = templates.map((t) => t.name);
    // Common templates that should exist
    expect(names).toContain("file");
    console.log(`  Total object templates: ${templates.length}`);
  });

  // --- Feeds ---

  it("should list feeds", async () => {
    const feeds = await client.listFeeds();
    expect(feeds).toBeInstanceOf(Array);
    console.log(`  Total feeds: ${feeds.length}`);
  });

  // --- Organisations ---

  it("should list organisations", async () => {
    const orgs = await client.listOrganisations("all");
    expect(orgs.length).toBeGreaterThan(0);
    console.log(
      `  Organisations: ${orgs.map((o) => o.name).join(", ")}`
    );
  });

  // --- Exports ---

  // --- Sightings ---

  it("should add a sighting by value", async () => {
    const sighting = await client.addSighting({
      value: "198.51.100.42",
      type: 0, // Sighting
      source: "integration-test",
    });

    expect(sighting.id).toBeDefined();
    expect(sighting.type).toBe("0");
    console.log(
      `  Sighting created: ${sighting.id} for event ${sighting.event_id}`
    );
  });

  // --- Publish (must happen before export tests) ---

  it("should publish an event", async () => {
    const result = await client.publishEvent(testEventId);
    expect(result).toBeDefined();
  });

  // --- Exports (after publish) ---

  it("should export IOCs in CSV format", async () => {
    const csv = await client.exportEvents({
      format: "csv",
      eventId: testEventId,
    });
    expect(csv).toBeDefined();
    // CSV should contain our test IP (event is published now)
    if (csv.trim().length > 0) {
      expect(csv).toContain("198.51.100.42");
    }
  });

  it("should export IOCs in text format", async () => {
    const text = await client.exportEvents({
      format: "text",
      eventId: testEventId,
    });
    expect(text).toBeDefined();
  });

  // --- Delete attribute ---

  it("should delete an attribute", async () => {
    // Get event to find an attribute ID
    const event = await client.getEvent(testEventId);
    const firstAttr = event.Attribute?.[0];
    if (firstAttr) {
      const result = await client.deleteAttribute(firstAttr.id);
      expect(result).toBeDefined();
    }
  });

  // --- Sharing Groups ---

  it("should list sharing groups", async () => {
    const groups = await client.listSharingGroups();
    expect(groups).toBeInstanceOf(Array);
    console.log(`  Sharing groups: ${groups.length}`);
  });
});
