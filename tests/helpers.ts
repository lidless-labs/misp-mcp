import { vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export type ToolHandler = (params: Record<string, unknown>) => Promise<unknown>;

export interface RegisteredToolInfo {
  description: string;
  schema: Record<string, unknown>;
  annotations: Record<string, unknown>;
  handler: ToolHandler;
}

type TextResult = { content?: Array<{ type: string; text?: string }>; isError?: boolean };

/** Strips the untrusted-data fence from successful text results. */
function unfenceResult(result: unknown): unknown {
  const r = result as TextResult;
  if (!r || r.isError || !Array.isArray(r.content)) return result;
  return {
    ...r,
    content: r.content.map((block) => {
      const match = block.text?.match(/^<untrusted_misp_data(?: [^>]*)?>\n([\s\S]*)\n<\/untrusted_misp_data>$/);
      return match ? { ...block, text: match[1] } : block;
    }),
  };
}

/**
 * Mock McpServer that records tool registrations. `handlers` return results
 * with the untrusted-data fence removed so assertions can parse JSON directly;
 * `registrations` keeps the raw handler for tests that check the fence itself.
 */
export function createToolHarness() {
  const handlers = new Map<string, ToolHandler>();
  const registrations = new Map<string, RegisteredToolInfo>();

  const mockServer = {
    tool: vi.fn((name: string, description: string, schema: Record<string, unknown>, annotations: Record<string, unknown>, handler: ToolHandler) => {
      registrations.set(name, { description, schema, annotations, handler });
      handlers.set(name, async (params) => unfenceResult(await handler(params)));
    }),
    resource: vi.fn(),
    prompt: vi.fn(),
  } as unknown as McpServer;

  return { mockServer, handlers, registrations };
}
