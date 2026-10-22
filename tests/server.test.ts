import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fetch } from "undici";

vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: vi.fn(),
}));
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMispMcpServer } from "../src/mcp-server.js";
import { MUTATING_TOOL_NAMES, TOOL_SPECS } from "../src/tool-specs.js";
import type { MispConfig } from "../src/config.js";

const config: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-key",
  verifySsl: true,
  timeout: 30000,
};

async function connect(env: Record<string, string | undefined> = {}) {
  const saved = process.env.MISP_ALLOWED_MUTATIONS;
  if (env.MISP_ALLOWED_MUTATIONS === undefined) delete process.env.MISP_ALLOWED_MUTATIONS;
  else process.env.MISP_ALLOWED_MUTATIONS = env.MISP_ALLOWED_MUTATIONS;

  try {
    const server = createMispMcpServer({ config });
    const client = new Client({ name: "test", version: "0.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    return { client, server };
  } finally {
    if (saved === undefined) delete process.env.MISP_ALLOWED_MUTATIONS;
    else process.env.MISP_ALLOWED_MUTATIONS = saved;
  }
}

describe("MCP server wiring", () => {
  beforeEach(() => {
    vi.mocked(fetch).mockReset();
  });

  afterEach(() => {
    vi.mocked(fetch).mockReset();
  });

  it("lists every tool with accurate annotations over the real protocol", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();

    expect(tools.map((t) => t.name).sort()).toEqual(Object.keys(TOOL_SPECS).sort());
    for (const tool of tools) {
      const spec = TOOL_SPECS[tool.name];
      expect(tool.annotations?.readOnlyHint, tool.name).toBe(!spec.mutating);
      expect(tool.annotations?.openWorldHint, tool.name).toBe(spec.openWorld ?? true);
    }
  });

  it("tells clients that MISP content is untrusted", async () => {
    const { client } = await connect();
    expect(client.getInstructions()).toContain("untrusted");
  });

  it("is read-only by default", async () => {
    const { client } = await connect();
    const result = await client.callTool({
      name: "misp_create_event",
      arguments: { info: "x", distribution: 0, threatLevel: 3, analysis: 0 },
    });

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("MISP_ALLOWED_MUTATIONS");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("enables only the tools named in MISP_ALLOWED_MUTATIONS", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(JSON.stringify({ Event: { id: "7", info: "x", uuid: "u", date: "2026-01-01", published: false } })),
    } as never);
    const { client } = await connect({ MISP_ALLOWED_MUTATIONS: "misp_create_event" });

    const created = await client.callTool({
      name: "misp_create_event",
      arguments: { info: "x", distribution: 0, threatLevel: 3, analysis: 0 },
    });
    expect(created.isError).toBeFalsy();
    expect(JSON.stringify(created.content)).toContain("untrusted_misp_data");

    const refused = await client.callTool({ name: "misp_update_event", arguments: { eventId: "7", info: "y" } });
    expect(refused.isError).toBe(true);
  });

  it("fails fast on an unknown tool name in MISP_ALLOWED_MUTATIONS", async () => {
    await expect(connect({ MISP_ALLOWED_MUTATIONS: "misp_creat_event" })).rejects.toThrow(/unknown tool name/);
  });

  it("covers every mutating tool in the spec table", () => {
    expect(MUTATING_TOOL_NAMES.length).toBe(15);
  });
});
