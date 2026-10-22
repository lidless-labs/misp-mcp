import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { fetch } from "undici";

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: vi.fn(),
}));
import { MispClient } from "../src/client.js";
import type { MispConfig } from "../src/config.js";
import { ALLOW_ALL_MUTATIONS } from "../src/guards.js";
import { registerEventTools } from "../src/tools/events.js";
import { registerAttributeTools } from "../src/tools/attributes.js";
import { registerTagTools } from "../src/tools/tags.js";
import { registerObjectTools } from "../src/tools/objects.js";
import { createToolHarness } from "./helpers.js";

const config: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-token",
  verifySsl: true,
  timeout: 30000,
};

type TextResult = { content: Array<{ type: string; text: string }>; isError?: boolean };

function setup() {
  const harness = createToolHarness();
  const client = new MispClient(config);
  registerEventTools(harness.mockServer, client, ALLOW_ALL_MUTATIONS);
  registerAttributeTools(harness.mockServer, client, ALLOW_ALL_MUTATIONS);
  registerTagTools(harness.mockServer, client, ALLOW_ALL_MUTATIONS);
  registerObjectTools(harness.mockServer, client, ALLOW_ALL_MUTATIONS);
  return harness;
}

function respondWith(body: unknown) {
  vi.mocked(fetch).mockReset().mockImplementation(
    vi.fn().mockResolvedValue({ ok: true, status: 200, text: () => Promise.resolve(JSON.stringify(body)) })
  );
}

function attributes(n: number) {
  return {
    response: {
      Attribute: Array.from({ length: n }, (_, i) => ({
        id: String(i + 1),
        event_id: "1",
        type: "domain",
        category: "Network activity",
        value: `h${i}.example`,
        to_ids: true,
      })),
    },
  };
}

function events(n: number) {
  return {
    response: Array.from({ length: n }, (_, i) => ({
      Event: { id: String(i + 1), info: `event ${i}`, date: "2026-01-01", threat_level_id: "3", analysis: "0", published: false },
    })),
  };
}

function requestBody() {
  const init = vi.mocked(fetch).mock.calls[0][1] as { body: string };
  return JSON.parse(init.body);
}

describe("limit and page validation", () => {
  const harness = setup();
  const schemaOf = (name: string) => z.object(harness.registrations.get(name)!.schema as z.ZodRawShape);

  it.each(["misp_search_events", "misp_search_attributes"])("%s validates limit", (name) => {
    const schema = schemaOf(name);
    expect(schema.safeParse({ limit: 1 }).success).toBe(true);
    expect(schema.safeParse({ limit: 500 }).success).toBe(true);
    for (const limit of [0, 501, 1.5, -1, 1_000_000, Number.NaN]) {
      expect(schema.safeParse({ limit }).success, `limit ${limit}`).toBe(false);
    }
  });

  it.each(["misp_search_events", "misp_search_attributes"])("%s validates page", (name) => {
    const schema = schemaOf(name);
    expect(schema.safeParse({ page: 1 }).success).toBe(true);
    expect(schema.safeParse({ page: 2 }).success).toBe(true);
    for (const page of [0, -1, 1.5]) {
      expect(schema.safeParse({ page }).success, `page ${page}`).toBe(false);
    }
  });

  it.each(["misp_list_tags", "misp_list_object_templates"])("%s bounds its limit", (name) => {
    const schema = schemaOf(name);
    expect(schema.safeParse({ limit: 10 }).success).toBe(true);
    expect(schema.safeParse({ limit: 0 }).success).toBe(false);
    expect(schema.safeParse({ limit: 501 }).success).toBe(false);
    expect(schema.safeParse({ limit: 2.5 }).success).toBe(false);
  });

  it("bounds distribution to 0-5, where 5 inherits the event setting", () => {
    const add = schemaOf("misp_add_attribute");
    const base = { eventId: "1", type: "domain", value: "x.example" };
    expect(add.safeParse({ ...base, distribution: 4 }).success).toBe(true);
    expect(add.safeParse({ ...base, distribution: 5 }).success).toBe(true);
    expect(add.safeParse({ ...base, distribution: 6 }).success).toBe(false);
    expect(add.safeParse({ ...base, distribution: 1.5 }).success).toBe(false);
  });
});

describe("attribute search paging", () => {
  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("sends page in the restSearch body", async () => {
    respondWith(attributes(1));
    await setup().handlers.get("misp_search_attributes")!({ value: "x", page: 2, limit: 10 });
    expect(requestBody()).toMatchObject({ page: 2, limit: 10, value: "x" });
  });

  it("omits page when not given", async () => {
    respondWith(attributes(1));
    await setup().handlers.get("misp_search_attributes")!({ value: "x" });
    expect(requestBody()).not.toHaveProperty("page");
    expect(requestBody().limit).toBe(50);
  });

  it("adds a more-results note only when the page is full", async () => {
    const { handlers } = setup();

    respondWith(attributes(3));
    const full = (await handlers.get("misp_search_attributes")!({ limit: 3 })) as TextResult;
    expect(full.content).toHaveLength(2);
    expect(full.content[1].text).toContain("more results may exist");
    expect(full.content[1].text).toContain("page: 2");
    expect(JSON.parse(full.content[0].text)).toHaveLength(3);

    respondWith(attributes(2));
    const partial = (await handlers.get("misp_search_attributes")!({ limit: 3 })) as TextResult;
    expect(partial.content).toHaveLength(1);
  });

  it("names the page after the one requested", async () => {
    respondWith(attributes(5));
    const result = (await setup().handlers.get("misp_search_attributes")!({ limit: 5, page: 4 })) as TextResult;
    expect(result.content[1].text).toContain("page: 5");
  });

  it("uses the default limit of 50 when none is given", async () => {
    respondWith(attributes(50));
    const result = (await setup().handlers.get("misp_search_attributes")!({})) as TextResult;
    expect(result.content[1].text).toContain("page: 2");
  });

  it("does not fence the server-written note", async () => {
    respondWith(attributes(2));
    const raw = (await setup().registrations.get("misp_search_attributes")!.handler({ limit: 2 })) as TextResult;
    expect(raw.content[0].text.startsWith("<untrusted_misp_data>")).toBe(true);
    expect(raw.content[1].text.startsWith("Note:")).toBe(true);
  });
});

describe("event search paging note", () => {
  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("adds the note only when the page is full and passes page through", async () => {
    const { handlers } = setup();

    respondWith(events(4));
    const full = (await handlers.get("misp_search_events")!({ limit: 4, page: 3 })) as TextResult;
    expect(requestBody()).toMatchObject({ page: 3, limit: 4 });
    expect(full.content[1].text).toContain("page: 4");

    respondWith(events(3));
    const partial = (await handlers.get("misp_search_events")!({ limit: 4 })) as TextResult;
    expect(partial.content).toHaveLength(1);
  });
});
