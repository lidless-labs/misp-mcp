import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { fetch } from "undici";

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: vi.fn(),
}));
import { MispClient } from "../src/client.js";
import type { MispConfig } from "../src/config.js";
import { ALLOW_ALL_MUTATIONS, parseMutationAllowlist } from "../src/guards.js";
import { registerSightingTools } from "../src/tools/sightings.js";
import { createToolHarness } from "./helpers.js";

const config: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-token",
  verifySsl: true,
  timeout: 30000,
};

type TextResult = { content: Array<{ type: string; text: string }>; isError?: boolean };

function respond(body: unknown, status = 200) {
  vi.mocked(fetch).mockReset().mockImplementation(
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      text: () => Promise.resolve(JSON.stringify(body)),
    })
  );
}

function sighting(i: number, type = "0") {
  return {
    Sighting: {
      id: String(i),
      attribute_id: "7",
      event_id: "3",
      org_id: "1",
      date_sighting: "1700000000",
      source: i % 2 ? "sensor-a" : "",
      type,
      Organisation: { id: "1", uuid: "u", name: "Example Org" },
    },
  };
}

describe("MispClient.listSightings", () => {
  const client = new MispClient(config);

  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("uses GET /sightings/index/{eventId} and unwraps Sighting", async () => {
    respond([sighting(1), sighting(2)]);
    const result = await client.listSightings("3");
    expect(result.map((s) => s.id)).toEqual(["1", "2"]);
    const [url, init] = vi.mocked(fetch).mock.calls[0] as unknown as [string, { method: string }];
    expect(url).toBe("https://misp.example.com/sightings/index/3");
    expect(init.method).toBe("GET");
  });

  it("accepts unwrapped sighting objects and non-array bodies", async () => {
    respond([sighting(1).Sighting]);
    expect((await client.listSightings("3"))[0].id).toBe("1");
    respond({});
    expect(await client.listSightings("3")).toEqual([]);
  });

  it("rejects an event id with path characters before sending", async () => {
    await expect(client.listSightings("3/../4")).rejects.toThrow(/Invalid eventId/);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it.each(["0", "00", "5f0e8a3c-9d3e-4a52-b6f1-0123456789ab"])("rejects event id %j, which MISP does not match to one event", async (id) => {
    await expect(client.listSightings(id)).rejects.toThrow(/Invalid eventId/);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });
});

describe("misp_list_sightings", () => {
  function setup() {
    const harness = createToolHarness();
    registerSightingTools(harness.mockServer, new MispClient(config), ALLOW_ALL_MUTATIONS);
    return harness;
  }

  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("maps types to labels and includes the organisation", async () => {
    respond([sighting(1, "0"), sighting(2, "1"), sighting(3, "2")]);
    const result = (await setup().handlers.get("misp_list_sightings")!({ eventId: "3" })) as TextResult;
    const data = JSON.parse(result.content[0].text);
    expect(data.map((s: { type: string }) => s.type)).toEqual(["Sighting", "False positive", "Expiration"]);
    expect(data[0]).toMatchObject({ id: "1", attribute_id: "7", event_id: "3", source: "sensor-a", organisation: "Example Org" });
    expect(data[1].source).toBeUndefined();
    expect(result.content).toHaveLength(1);
  });

  it("handles an empty result", async () => {
    respond([]);
    const result = (await setup().handlers.get("misp_list_sightings")!({ eventId: "3" })) as TextResult;
    expect(result.content[0].text).toContain("No sightings found for event 3");
  });

  it("truncates to limit and says so", async () => {
    respond(Array.from({ length: 5 }, (_, i) => sighting(i + 1)));
    const result = (await setup().handlers.get("misp_list_sightings")!({ eventId: "3", limit: 2 })) as TextResult;
    expect(JSON.parse(result.content[0].text)).toHaveLength(2);
    expect(result.content[1].text).toContain("showing the first 2 of 5 sightings");
  });

  it("defaults to 100 and notes truncation", async () => {
    respond(Array.from({ length: 120 }, (_, i) => sighting(i + 1)));
    const result = (await setup().handlers.get("misp_list_sightings")!({ eventId: "3" })) as TextResult;
    expect(JSON.parse(result.content[0].text)).toHaveLength(100);
    expect(result.content[1].text).toContain("first 100 of 120");
  });

  it("adds no note when nothing was cut", async () => {
    respond([sighting(1), sighting(2)]);
    const result = (await setup().handlers.get("misp_list_sightings")!({ eventId: "3", limit: 2 })) as TextResult;
    expect(result.content).toHaveLength(1);
  });

  it("returns an upstream error", async () => {
    respond({ message: "denied" }, 403);
    const result = (await setup().handlers.get("misp_list_sightings")!({ eventId: "3" })) as TextResult;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Insufficient permissions");
  });

  it("is read-only and works without any mutation allowed", async () => {
    respond([sighting(1)]);
    const harness = createToolHarness();
    registerSightingTools(harness.mockServer, new MispClient(config), parseMutationAllowlist(undefined));
    const result = (await harness.handlers.get("misp_list_sightings")!({ eventId: "3" })) as TextResult;
    expect(result.isError).toBeUndefined();
    expect(harness.registrations.get("misp_list_sightings")!.annotations).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    });
  });

  it("bounds limit to 1-500", () => {
    const schema = z.object(setup().registrations.get("misp_list_sightings")!.schema as z.ZodRawShape);
    expect(schema.safeParse({ eventId: "3", limit: 500 }).success).toBe(true);
    for (const limit of [0, 501, 1.5]) {
      expect(schema.safeParse({ eventId: "3", limit }).success, `limit ${limit}`).toBe(false);
    }
  });
});
