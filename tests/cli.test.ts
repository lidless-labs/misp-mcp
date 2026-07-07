import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { HELP, parseArgs, run, type MispCtrlDeps } from "../src/cli.js";
import {
  CliGateError,
  requireDestructiveCliGate,
  requireHardDeleteCliGate,
} from "../src/cli-safety.js";
import type { MispClient } from "../src/client.js";
import type { MispConfig } from "../src/config.js";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { bin?: Record<string, string> };

const mockConfig: MispConfig = {
  url: "https://misp.example.com",
  apiKey: "test-api-key-123",
  verifySsl: true,
  timeout: 30_000,
};

function capture(client: Partial<MispClient>, deps: Partial<MispCtrlDeps> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const resolvedDeps: Partial<MispCtrlDeps> = {
    out: (text) => out.push(text),
    err: (text) => err.push(text),
    getConfig: () => mockConfig,
    makeClient: () => client as MispClient,
    serve: vi.fn().mockResolvedValue(undefined),
    ...deps,
  };
  return { out, err, deps: resolvedDeps };
}

function eventFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: "42",
    orgc_id: "1",
    org_id: "1",
    info: "Suspicious infrastructure",
    date: "2026-07-06",
    threat_level_id: "2",
    analysis: "1",
    distribution: "1",
    published: false,
    uuid: "event-42",
    timestamp: "1783320000",
    publish_timestamp: "0",
    attribute_count: "3",
    Orgc: { id: "1", name: "SOC", uuid: "org-1" },
    Tag: [{ id: "1", name: "tlp:amber", colour: "#ffc000", exportable: true }],
    Attribute: [
      {
        id: "100",
        event_id: "42",
        type: "domain",
        category: "Network activity",
        value: "evil.example",
        to_ids: true,
        uuid: "attr-100",
        timestamp: "1783320000",
        distribution: "1",
        comment: "",
        deleted: false,
      },
    ],
    Object: [],
    RelatedEvent: [],
    ...overrides,
  };
}

describe("mispctrl CLI", () => {
  it("documents mispctrl as primary and keeps compatibility bins", () => {
    expect(HELP).toContain("mispctrl - MISP threat-intelligence control CLI");
    expect(HELP).toContain("alias: mispctl");
    expect(packageJson.bin).toMatchObject({
      mispctrl: "./dist/cli.js",
      mispctl: "./dist/cli.js",
      "misp-mcp": "./dist/mcp-bin.js",
    });
  });

  it("parses first-slice commands", () => {
    expect(parseArgs(["status", "--json"])).toEqual({ kind: "status", json: true });
    expect(parseArgs(["events", "list", "--limit", "10", "--tag", "tlp:amber"])).toEqual({
      kind: "events list",
      json: false,
      limit: 10,
      page: undefined,
      value: undefined,
      type: undefined,
      category: undefined,
      tags: ["tlp:amber"],
      org: undefined,
      last: undefined,
      published: undefined,
    });
    expect(parseArgs(["events", "get", "42"])).toEqual({
      kind: "events get",
      json: false,
      eventId: "42",
    });
  });

  it("runs mispctrl status --json as a setup smoke test", async () => {
    const client = {
      getVersion: vi.fn().mockResolvedValue({
        version: "2.5.12",
        pymisp_recommended_version: "2.5.12",
        perm_sync: true,
        perm_sighting: true,
        perm_galaxy_editor: false,
        perm_analyst_data: true,
      }),
      getServerSettings: vi.fn().mockResolvedValue({
        diagnostics: { workers: "ok" },
      }),
    };
    const { out, deps } = capture(client);

    await expect(run(["status", "--json"], deps)).resolves.toBe(0);

    const data = JSON.parse(out[0]) as Record<string, any>;
    expect(data.healthy).toBe(true);
    expect(data.url).toBe("https://misp.example.com");
    expect(data.version).toBe("2.5.12");
    expect(data.permissions.sync).toBe(true);
    expect(client.getVersion).toHaveBeenCalledTimes(1);
  });

  it("runs mispctrl events list with filters", async () => {
    const client = {
      searchEvents: vi.fn().mockResolvedValue([eventFixture()]),
    };
    const { out, deps } = capture(client);

    await expect(
      run(["events", "list", "--limit", "5", "--value", "evil.example", "--tag", "tlp:amber"], deps),
    ).resolves.toBe(0);

    expect(client.searchEvents).toHaveBeenCalledWith({
      value: "evil.example",
      type: undefined,
      category: undefined,
      tags: ["tlp:amber"],
      org: undefined,
      last: undefined,
      published: undefined,
      limit: 5,
      page: undefined,
    });
    expect(out.join("\n")).toContain("events count=1 limit=5");
    expect(out.join("\n")).toContain("id=42");
  });

  it("runs mispctrl events get --json", async () => {
    const client = {
      getEvent: vi.fn().mockResolvedValue(eventFixture()),
    };
    const { out, deps } = capture(client);

    await expect(run(["events", "get", "42", "--json"], deps)).resolves.toBe(0);

    const data = JSON.parse(out[0]) as Record<string, any>;
    expect(data.id).toBe("42");
    expect(data.attributes).toHaveLength(1);
    expect(data.attributes[0].value).toBe("evil.example");
    expect(client.getEvent).toHaveBeenCalledWith("42");
  });

  it("redacts API keys from CLI errors", async () => {
    const client = {
      getEvent: vi.fn().mockRejectedValue(new Error("failed Authorization: test-api-key-123")),
    };
    const { err, deps } = capture(client);

    await expect(run(["events", "get", "42"], deps)).resolves.toBe(1);

    expect(err.join("\n")).not.toContain("test-api-key-123");
    expect(err.join("\n")).toContain("[REDACTED]");
  });

  it("delegates mispctrl mcp to the MCP server", async () => {
    const serve = vi.fn().mockResolvedValue(undefined);
    const { deps } = capture({}, { serve });

    await expect(run(["mcp"], deps)).resolves.toBe(0);

    expect(serve).toHaveBeenCalledTimes(1);
  });
});

describe("mispctrl safety gates", () => {
  it("requires env opt-in plus flags for destructive CLI commands", () => {
    expect(() =>
      requireDestructiveCliGate({
        commandName: "misp events delete",
        env: {},
        confirm: true,
        destructive: true,
      }),
    ).toThrow(CliGateError);

    expect(() =>
      requireDestructiveCliGate({
        commandName: "misp events delete",
        env: { MISP_ALLOW_DESTRUCTIVE: "true" },
        confirm: true,
        destructive: false,
      }),
    ).toThrow("--confirm and --destructive");

    expect(() =>
      requireDestructiveCliGate({
        commandName: "misp events delete",
        env: { MISP_ALLOW_DESTRUCTIVE: "true" },
        confirm: true,
        destructive: true,
      }),
    ).not.toThrow();
  });

  it("requires a second confirmation for hard deletes", () => {
    expect(() =>
      requireHardDeleteCliGate({
        commandName: "misp attributes delete",
        env: { MISP_ALLOW_DESTRUCTIVE: "true" },
        confirm: true,
        destructive: true,
        confirmHard: false,
      }),
    ).toThrow("--confirm-hard");

    expect(() =>
      requireHardDeleteCliGate({
        commandName: "misp attributes delete",
        env: { MISP_ALLOW_DESTRUCTIVE: "true" },
        confirm: true,
        destructive: true,
        confirmHard: true,
      }),
    ).not.toThrow();
  });
});
