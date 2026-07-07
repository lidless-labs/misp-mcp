import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getConfig, type MispConfig } from "./config.js";
import { MispClient } from "./client.js";
import { serveMcp } from "./mcp-server.js";
import { safeCaughtErrorMessage } from "./safe-error.js";
import type { MispEvent } from "./types.js";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { version?: string };

export const HELP = `mispctrl - MISP threat-intelligence control CLI (alias: mispctl; MCP adapter: misp-mcp)

Usage:
  mispctrl <command> [options]

Commands:
  status [--json]              Validate MISP URL, API key, TLS setting, and version endpoint
  events list [options]        List/search MISP events
  events get <event-id>        Get one MISP event
  mcp                          Start the MCP server over stdio
  help                         Show this help
  --version                    Show package version

Event list options:
  --limit <n>                  Max events to return (default: 20, max: 100)
  --page <n>                   Page number
  --value <ioc>                IOC value search
  --type <type>                Attribute type filter
  --category <category>        Attribute category filter
  --tag <tag>                  Tag filter, repeatable
  --org <org>                  Organization filter
  --last <window>              Relative time, for example 1d, 7d, 30d
  --published                  Only published events

Global options:
  --json                       Emit JSON instead of a concise summary
`;

type Parsed =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "mcp" }
  | { kind: "status"; json: boolean }
  | {
      kind: "events list";
      json: boolean;
      limit: number;
      page?: number;
      value?: string;
      type?: string;
      category?: string;
      tags?: string[];
      org?: string;
      last?: string;
      published?: boolean;
    }
  | { kind: "events get"; json: boolean; eventId: string };

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export interface MispCtrlDeps {
  out: (text: string) => void;
  err: (text: string) => void;
  getConfig: () => MispConfig;
  makeClient: (config: MispConfig) => MispClient;
  serve: () => Promise<void>;
}

const DEFAULT_DEPS: MispCtrlDeps = {
  out: (text) => console.log(text),
  err: (text) => console.error(text),
  getConfig,
  makeClient: (config) => new MispClient(config),
  serve: serveMcp,
};

function stripJson(args: string[]): { args: string[]; json: boolean } {
  let json = false;
  const rest: string[] = [];
  for (const arg of args) {
    if (arg === "--json") json = true;
    else rest.push(arg);
  }
  return { args: rest, json };
}

function flagValue(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new UsageError(`${flag} requires a value`);
  return value;
}

function intFlag(value: string, flag: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new UsageError(`${flag} must be an integer from ${min} to ${max}`);
  }
  return parsed;
}

function parseEventsListOptions(args: string[], json: boolean): Extract<Parsed, { kind: "events list" }> {
  let limit = 20;
  let page: number | undefined;
  let value: string | undefined;
  let type: string | undefined;
  let category: string | undefined;
  let org: string | undefined;
  let last: string | undefined;
  let published: boolean | undefined;
  const tags: string[] = [];

  for (let i = 0; i < args.length; i += 1) {
    const option = args[i];
    if (option === "--limit") {
      limit = intFlag(flagValue(args, i, option), option, 1, 100);
      i += 1;
    } else if (option === "--page") {
      page = intFlag(flagValue(args, i, option), option, 1, 100_000);
      i += 1;
    } else if (option === "--value") {
      value = flagValue(args, i, option);
      i += 1;
    } else if (option === "--type") {
      type = flagValue(args, i, option);
      i += 1;
    } else if (option === "--category") {
      category = flagValue(args, i, option);
      i += 1;
    } else if (option === "--tag") {
      tags.push(flagValue(args, i, option));
      i += 1;
    } else if (option === "--org") {
      org = flagValue(args, i, option);
      i += 1;
    } else if (option === "--last") {
      last = flagValue(args, i, option);
      i += 1;
    } else if (option === "--published") {
      published = true;
    } else {
      throw new UsageError(`Unknown events list option: ${option}`);
    }
  }

  return {
    kind: "events list",
    json,
    limit,
    page,
    value,
    type,
    category,
    tags: tags.length > 0 ? tags : undefined,
    org,
    last,
    published,
  };
}

export function parseArgs(rawArgs: string[]): Parsed {
  const { args, json } = stripJson(rawArgs);
  const [first, second, third, ...rest] = args;

  if (!first || first === "help" || first === "--help" || first === "-h") return { kind: "help" };
  if (first === "--version" || first === "version") return { kind: "version" };
  if (first === "mcp") return { kind: "mcp" };
  if (first === "status") {
    if (second) throw new UsageError(`Unknown status option: ${second}`);
    return { kind: "status", json };
  }
  if (first === "events" && second === "list") {
    const options = third ? [third, ...rest] : rest;
    return parseEventsListOptions(options, json);
  }
  if (first === "events" && second === "get") {
    if (!third) throw new UsageError("events get requires an event id");
    if (rest.length > 0) throw new UsageError(`Unknown events get option: ${rest[0]}`);
    return { kind: "events get", json, eventId: third };
  }

  throw new UsageError(`Unknown command: ${args.join(" ")}`);
}

function compactLine(values: Array<string | undefined>): string {
  return values.filter(Boolean).join(" ");
}

function eventSummary(event: MispEvent): Record<string, unknown> {
  return {
    id: event.id,
    uuid: event.uuid,
    date: event.date,
    info: event.info,
    threat_level_id: event.threat_level_id,
    analysis: event.analysis,
    distribution: event.distribution,
    published: event.published,
    org: event.Orgc?.name ?? event.Org?.name,
    attribute_count: event.attribute_count,
    tags: (event.Tag ?? []).map((tag) => tag.name),
  };
}

function eventDetail(event: MispEvent): Record<string, unknown> {
  return {
    ...eventSummary(event),
    attributes: (event.Attribute ?? []).map((attribute) => ({
      id: attribute.id,
      type: attribute.type,
      category: attribute.category,
      value: attribute.value,
      to_ids: attribute.to_ids,
      deleted: attribute.deleted,
    })),
    objects: (event.Object ?? []).map((object) => ({
      id: object.id,
      name: object.name,
      meta_category: object.meta_category,
      attribute_count: object.Attribute?.length ?? 0,
    })),
    related_events: (event.RelatedEvent ?? []).map((related) => ({
      id: related.Event.id,
      date: related.Event.date,
      info: related.Event.info,
    })),
  };
}

async function runStatus(parsed: Extract<Parsed, { kind: "status" }>, client: MispClient, config: MispConfig) {
  const version = await client.getVersion();
  let diagnostics: unknown;
  try {
    diagnostics = (await client.getServerSettings()).diagnostics;
  } catch {
    diagnostics = undefined;
  }
  const result = {
    healthy: true,
    url: config.url,
    verify_ssl: config.verifySsl,
    timeout_ms: config.timeout,
    version: version.version,
    pymisp_recommended_version: version.pymisp_recommended_version,
    permissions: {
      sync: version.perm_sync,
      sighting: version.perm_sighting,
      galaxy_editor: version.perm_galaxy_editor,
      analyst_data: version.perm_analyst_data,
    },
    diagnostics,
  };
  if (parsed.json) return { code: 0, text: JSON.stringify(result, null, 2) };
  return {
    code: 0,
    text: compactLine([
      "status=ok",
      `version=${version.version}`,
      `pymisp=${version.pymisp_recommended_version}`,
      `url=${config.url}`,
      `verify_ssl=${String(config.verifySsl)}`,
    ]),
  };
}

async function runEventsList(parsed: Extract<Parsed, { kind: "events list" }>, client: MispClient) {
  const events = await client.searchEvents({
    value: parsed.value,
    type: parsed.type,
    category: parsed.category,
    tags: parsed.tags,
    org: parsed.org,
    last: parsed.last,
    published: parsed.published,
    limit: parsed.limit,
    page: parsed.page,
  });
  const result = {
    events: events.map(eventSummary),
    count: events.length,
    limit: parsed.limit,
  };
  if (parsed.json) return { code: 0, text: JSON.stringify(result, null, 2) };
  const lines = [`events count=${events.length} limit=${parsed.limit}`];
  for (const event of result.events) {
    lines.push(
      compactLine([
        `id=${event.id}`,
        event.date ? `date=${event.date}` : undefined,
        event.published !== undefined ? `published=${String(event.published)}` : undefined,
        event.attribute_count ? `attributes=${event.attribute_count}` : undefined,
        event.info ? `info=${JSON.stringify(event.info)}` : undefined,
      ]),
    );
  }
  return { code: 0, text: lines.join("\n") };
}

async function runEventsGet(parsed: Extract<Parsed, { kind: "events get" }>, client: MispClient) {
  const event = await client.getEvent(parsed.eventId);
  const result = eventDetail(event);
  if (parsed.json) return { code: 0, text: JSON.stringify(result, null, 2) };
  return {
    code: 0,
    text: compactLine([
      `id=${result.id}`,
      result.date ? `date=${result.date}` : undefined,
      result.published !== undefined ? `published=${String(result.published)}` : undefined,
      result.attribute_count ? `attributes=${result.attribute_count}` : undefined,
      result.info ? `info=${JSON.stringify(result.info)}` : undefined,
    ]),
  };
}

export async function run(rawArgs: string[], deps: Partial<MispCtrlDeps> = {}): Promise<number> {
  const resolvedDeps = { ...DEFAULT_DEPS, ...deps };
  let parsed: Parsed;
  try {
    parsed = parseArgs(rawArgs);
  } catch (error) {
    if (error instanceof UsageError) {
      resolvedDeps.err(error.message);
      resolvedDeps.err("Run mispctrl help for usage.");
      return 2;
    }
    throw error;
  }

  if (parsed.kind === "help") {
    resolvedDeps.out(HELP);
    return 0;
  }
  if (parsed.kind === "version") {
    resolvedDeps.out(packageJson.version ?? "0.0.0");
    return 0;
  }
  if (parsed.kind === "mcp") {
    await resolvedDeps.serve();
    return 0;
  }

  let config: MispConfig | undefined;
  try {
    config = resolvedDeps.getConfig();
    const client = resolvedDeps.makeClient(config);
    const result =
      parsed.kind === "status"
        ? await runStatus(parsed, client, config)
        : parsed.kind === "events list"
          ? await runEventsList(parsed, client)
          : await runEventsGet(parsed, client);
    resolvedDeps.out(result.text);
    return result.code;
  } catch (error) {
    resolvedDeps.err(
      JSON.stringify({
        error: safeCaughtErrorMessage(error, "Unexpected error", [config?.apiKey ?? ""]),
      }),
    );
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
