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
import { registerAttributeTools } from "../src/tools/attributes.js";
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

function lastCall() {
  const [url, init] = vi.mocked(fetch).mock.calls[0] as unknown as [string, { method: string; body?: string }];
  return { url, method: init.method, body: init.body ? JSON.parse(init.body) : undefined };
}

const attribute = {
  id: "7",
  event_id: "3",
  uuid: "00000000-0000-4000-8000-000000000007",
  type: "domain",
  category: "Network activity",
  value: "bad.example",
  to_ids: true,
  comment: "seen in phishing",
  distribution: "1",
  timestamp: "1700000000",
  deleted: false,
  Tag: [{ id: "1", name: "tlp:amber" }],
  Event: { info: "Phishing wave" },
  RelatedAttribute: [{ id: "9", value: "bad.example", type: "domain", event_id: "4" }],
};

describe("MispClient attribute read and edit", () => {
  const client = new MispClient(config);

  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("getAttribute uses GET /attributes/view/{id} and unwraps the Attribute", async () => {
    respond({ Attribute: attribute });
    const result = await client.getAttribute("7");
    expect(result.value).toBe("bad.example");
    expect(lastCall()).toMatchObject({ url: "https://misp.example.com/attributes/view/7", method: "GET" });
  });

  it("updateAttribute uses PUT /attributes/edit/{id} with only the given fields", async () => {
    respond({ Attribute: { ...attribute, to_ids: false } });
    const result = await client.updateAttribute("7", { to_ids: false, comment: "fixed", disable_correlation: true, distribution: 0 });
    expect(result.to_ids).toBe(false);
    expect(lastCall()).toEqual({
      url: "https://misp.example.com/attributes/edit/7",
      method: "PUT",
      body: { to_ids: false, comment: "fixed", disable_correlation: true, distribution: 0 },
    });
  });

  it("updateAttribute sends value, type and category when given", async () => {
    respond({ Attribute: attribute });
    await client.updateAttribute("7", { value: "good.example", type: "hostname", category: "Network activity" });
    expect(lastCall().body).toEqual({ value: "good.example", type: "hostname", category: "Network activity" });
  });

  it("never forwards an event id", async () => {
    respond({ Attribute: attribute });
    await client.updateAttribute("7", { value: "x", event_id: "99" } as never);
    expect(lastCall().body).toEqual({ value: "x" });
  });

  it.each(["../events/delete/1", "7/../8", "7?x=1", "7#a", "a b", ""])("rejects attribute id %j without a request", async (id) => {
    await expect(client.getAttribute(id)).rejects.toThrow(/Invalid attributeId/);
    await expect(client.updateAttribute(id, { value: "x" })).rejects.toThrow(/Invalid attributeId/);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("encodes ids in the path", async () => {
    respond({ Attribute: attribute });
    await client.getAttribute("abc-123_DEF");
    expect(lastCall().url).toBe("https://misp.example.com/attributes/view/abc-123_DEF");
  });
});

describe("misp_get_attribute and misp_update_attribute tools", () => {
  function setup(policy = ALLOW_ALL_MUTATIONS) {
    const harness = createToolHarness();
    registerAttributeTools(harness.mockServer, new MispClient(config), policy);
    return harness;
  }

  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("misp_get_attribute returns tags and correlations", async () => {
    respond({ Attribute: attribute });
    const result = (await setup().handlers.get("misp_get_attribute")!({ attributeId: "7" })) as TextResult;
    const data = JSON.parse(result.content[0].text);
    expect(data).toMatchObject({ id: "7", event_id: "3", value: "bad.example", tags: ["tlp:amber"], event_info: "Phishing wave" });
    expect(data.correlations).toEqual([{ value: "bad.example", type: "domain", event_id: "4" }]);
  });

  it("misp_get_attribute reports an upstream error", async () => {
    respond({ message: "gone" }, 404);
    const result = (await setup().handlers.get("misp_get_attribute")!({ attributeId: "7" })) as TextResult;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Resource not found");
  });

  it("misp_update_attribute edits in place without a confirm flag", async () => {
    respond({ Attribute: { ...attribute, to_ids: false } });
    const result = (await setup().handlers.get("misp_update_attribute")!({ attributeId: "7", toIds: false, disableCorrelation: true })) as TextResult;
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(result.content[0].text).to_ids).toBe(false);
    expect(lastCall().body).toEqual({ to_ids: false, disable_correlation: true });
  });

  it("rejects an empty update before sending a request", async () => {
    const result = (await setup().handlers.get("misp_update_attribute")!({ attributeId: "7" })) as TextResult;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("at least one field");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("reports an upstream error from the edit call", async () => {
    respond({ message: "Attribute could not be saved" }, 403);
    const result = (await setup().handlers.get("misp_update_attribute")!({ attributeId: "7", comment: "x" })) as TextResult;
    expect(result.isError).toBe(true);
  });

  it("is behind the mutation gate", async () => {
    const result = (await setup(parseMutationAllowlist(undefined)).handlers.get("misp_update_attribute")!({ attributeId: "7", comment: "x" })) as TextResult;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("MISP_ALLOWED_MUTATIONS");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("declares accurate annotations", () => {
    const { registrations } = setup();
    expect(registrations.get("misp_get_attribute")!.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true });
    expect(registrations.get("misp_update_attribute")!.annotations).toMatchObject({ readOnlyHint: false, idempotentHint: true });
  });

  it("validates the update schema", () => {
    const schema = z.object(setup().registrations.get("misp_update_attribute")!.schema as z.ZodRawShape);
    expect(schema.safeParse({ attributeId: "7", comment: "" }).success).toBe(true);
    expect(schema.safeParse({ attributeId: "7", value: "" }).success).toBe(false);
    expect(schema.safeParse({ attributeId: "7", distribution: 5 }).success).toBe(false);
    expect(schema.safeParse({ attributeId: "7", toIds: "yes" }).success).toBe(false);
  });
});
