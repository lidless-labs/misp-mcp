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
import { registerEventReportTools } from "../src/tools/event-reports.js";
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

function lastCall(index = 0) {
  const [url, init] = vi.mocked(fetch).mock.calls[index] as unknown as [string, { method: string; body?: string }];
  return { url, method: init.method, body: init.body ? JSON.parse(init.body) : undefined };
}

function report(id: number, eventId = "3", extra: Record<string, unknown> = {}) {
  return {
    EventReport: {
      id: String(id),
      uuid: `00000000-0000-4000-8000-00000000000${id}`,
      event_id: eventId,
      name: `Report ${id}`,
      content: `# Report ${id}`,
      distribution: "0",
      timestamp: "1700000000",
      ...extra,
    },
  };
}

describe("MispClient event reports", () => {
  const client = new MispClient(config);

  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("listEventReports asks MISP for one event and still filters the result", async () => {
    respond([report(1, "3"), report(2, "4"), report(3, "3")]);
    const result = await client.listEventReports("3");
    expect(result.map((r) => r.id)).toEqual(["1", "3"]);
    expect(lastCall()).toMatchObject({ url: "https://misp.example.com/eventReports/index/event_id:3", method: "GET" });
  });

  it("listEventReports tolerates unwrapped entries and non-array bodies", async () => {
    respond([report(1, "3").EventReport]);
    expect(await client.listEventReports("3")).toHaveLength(1);
    respond({});
    expect(await client.listEventReports("3")).toEqual([]);
  });

  it("getEventReport uses GET /eventReports/view/{id}", async () => {
    respond(report(7));
    const result = await client.getEventReport("7");
    expect(result.name).toBe("Report 7");
    expect(lastCall()).toMatchObject({ url: "https://misp.example.com/eventReports/view/7", method: "GET" });
  });

  it("addEventReport uses POST /eventReports/add/{eventId} with name, content and distribution", async () => {
    respond(report(9));
    await client.addEventReport("3", { name: "N", content: "# C", distribution: 1 });
    expect(lastCall()).toEqual({
      url: "https://misp.example.com/eventReports/add/3",
      method: "POST",
      body: { name: "N", content: "# C", distribution: 1 },
    });
  });

  it("addEventReport omits distribution when not given", async () => {
    respond(report(9));
    await client.addEventReport("3", { name: "N", content: "# C" });
    expect(lastCall().body).toEqual({ name: "N", content: "# C" });
  });

  it.each(["3/../4", "3?x=1", "a b", ""])("rejects id %j without a request", async (id) => {
    await expect(client.listEventReports(id)).rejects.toThrow(/Invalid eventId/);
    await expect(client.getEventReport(id)).rejects.toThrow(/Invalid eventReportId/);
    await expect(client.addEventReport(id, { name: "n", content: "c" })).rejects.toThrow(/Invalid eventId/);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });
});

describe("event report tools", () => {
  function setup(policy = ALLOW_ALL_MUTATIONS) {
    const harness = createToolHarness();
    registerEventReportTools(harness.mockServer, new MispClient(config), policy);
    return harness;
  }

  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("misp_list_event_reports lists summaries without content", async () => {
    respond([report(1), report(2, "4")]);
    const result = (await setup().handlers.get("misp_list_event_reports")!({ eventId: "3" })) as TextResult;
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveLength(1);
    expect(data[0]).toMatchObject({ id: "1", name: "Report 1", distribution: "Organization" });
    expect(data[0]).not.toHaveProperty("content");
  });

  it("misp_list_event_reports bounds output by limit and says so", async () => {
    respond(Array.from({ length: 5 }, (_, i) => report(i + 1)));
    const result = (await setup().handlers.get("misp_list_event_reports")!({ eventId: "3", limit: 2 })) as TextResult;
    expect(JSON.parse(result.content[0].text)).toHaveLength(2);
    expect(result.content[1].text).toContain("first 2 of 5 reports");
  });

  it("misp_list_event_reports handles no reports and upstream errors", async () => {
    respond([report(1, "9")]);
    const none = (await setup().handlers.get("misp_list_event_reports")!({ eventId: "3" })) as TextResult;
    expect(none.content[0].text).toContain("No event reports found for event 3");

    respond({ message: "denied" }, 403);
    const failed = (await setup().handlers.get("misp_list_event_reports")!({ eventId: "3" })) as TextResult;
    expect(failed.isError).toBe(true);
  });

  it("misp_get_event_report returns the content", async () => {
    respond(report(7, "3", { content: "## Findings\n\nDetails" }));
    const result = (await setup().handlers.get("misp_get_event_report")!({ eventReportId: "7" })) as TextResult;
    expect(JSON.parse(result.content[0].text)).toMatchObject({ id: "7", content: "## Findings\n\nDetails" });
    expect(result.content).toHaveLength(1);
  });

  it("misp_get_event_report cuts very long content and says so", async () => {
    respond(report(7, "3", { content: "x".repeat(60_000) }));
    const result = (await setup().handlers.get("misp_get_event_report")!({ eventReportId: "7" })) as TextResult;
    expect(JSON.parse(result.content[0].text).content).toHaveLength(50_000);
    expect(result.content[1].text).toContain("50000 of 60000");
  });

  it("misp_get_event_report returns an upstream error", async () => {
    respond({ message: "nope" }, 404);
    const result = (await setup().handlers.get("misp_get_event_report")!({ eventReportId: "7" })) as TextResult;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Resource not found");
  });

  it("misp_add_event_report runs without a confirm flag and returns identifiers", async () => {
    respond(report(11, "3", { distribution: "1" }));
    const result = (await setup().handlers.get("misp_add_event_report")!({
      eventId: "3",
      name: "Report 11",
      content: "# Summary",
      distribution: 1,
    })) as TextResult;
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(result.content[0].text)).toMatchObject({ id: "11", event_id: "3", distribution: "Community" });
    expect(lastCall().body).toEqual({ name: "Report 11", content: "# Summary", distribution: 1 });
  });

  it("misp_add_event_report returns an upstream error", async () => {
    respond({ message: "invalid" }, 403);
    const result = (await setup().handlers.get("misp_add_event_report")!({ eventId: "3", name: "n", content: "c" })) as TextResult;
    expect(result.isError).toBe(true);
  });

  it("misp_add_event_report is behind the mutation gate but readable tools are not", async () => {
    const harness = setup(parseMutationAllowlist(undefined));
    const refused = (await harness.handlers.get("misp_add_event_report")!({ eventId: "3", name: "n", content: "c" })) as TextResult;
    expect(refused.isError).toBe(true);
    expect(refused.content[0].text).toContain("MISP_ALLOWED_MUTATIONS");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();

    respond([report(1)]);
    const listed = (await harness.handlers.get("misp_list_event_reports")!({ eventId: "3" })) as TextResult;
    expect(listed.isError).toBeUndefined();
  });

  it("rejects content over 1 MB and empty names in the schema", () => {
    const schema = z.object(setup().registrations.get("misp_add_event_report")!.schema as z.ZodRawShape);
    const base = { eventId: "3", name: "n" };
    expect(schema.safeParse({ ...base, content: "x".repeat(1_000_000) }).success).toBe(true);
    expect(schema.safeParse({ ...base, content: "x".repeat(1_000_001) }).success).toBe(false);
    // multi-byte characters count by bytes
    expect(schema.safeParse({ ...base, content: "é".repeat(500_001) }).success).toBe(false);
    expect(schema.safeParse({ ...base, content: "" }).success).toBe(false);
    expect(schema.safeParse({ eventId: "3", name: "", content: "c" }).success).toBe(false);
  });

  it("limits distribution to 0-3 (sharing groups are not supported)", () => {
    const schema = z.object(setup().registrations.get("misp_add_event_report")!.schema as z.ZodRawShape);
    const base = { eventId: "3", name: "n", content: "c" };
    expect(schema.safeParse({ ...base, distribution: 3 }).success).toBe(true);
    expect(schema.safeParse({ ...base, distribution: 4 }).success).toBe(false);
    expect(schema.safeParse({ ...base, distribution: 0.5 }).success).toBe(false);
  });

  it("declares accurate annotations", () => {
    const { registrations } = setup();
    for (const name of ["misp_list_event_reports", "misp_get_event_report"]) {
      expect(registrations.get(name)!.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true });
    }
    expect(registrations.get("misp_add_event_report")!.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    });
  });
});
