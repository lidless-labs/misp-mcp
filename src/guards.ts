import { parseBooleanEnv } from "./env.js";
import { MUTATING_TOOL_NAMES } from "./tool-specs.js";

/**
 * Safety guards for destructive / state-changing MISP tools.
 *
 * Every tool that changes MISP state is also behind a mutation allowlist: the
 * server is read-only unless the operator names the tools (or `*`) in
 * MISP_ALLOWED_MUTATIONS.
 *
 * Destructive tools (delete, publish, untag) are gated behind an explicit
 * `confirm: true` argument by default. As an alternative for trusted
 * automation, the env var MISP_ALLOW_DESTRUCTIVE=true pre-authorizes the
 * confirmation so the `confirm` flag is no longer required.
 *
 * Permanent ("hard") deletes always require a second, explicit confirmation
 * (`confirmHard: true`) regardless of the env opt-in, since they are
 * irreversible.
 */

/**
 * True when destructive actions are pre-authorized via environment. Accepts
 * true/1/false/0 (see parseBooleanEnv); an unparseable value throws, so the
 * guarded call fails closed.
 */
export function destructiveEnvOptIn(env: NodeJS.ProcessEnv = process.env): boolean {
  return parseBooleanEnv("MISP_ALLOW_DESTRUCTIVE", env.MISP_ALLOW_DESTRUCTIVE, false);
}

/** Operator-controlled set of state-changing tools that may run. */
export interface MutationPolicy {
  readonly all: boolean;
  readonly tools: ReadonlySet<string>;
  allows(tool: string): boolean;
}

function buildPolicy(all: boolean, tools: Set<string>): MutationPolicy {
  return { all, tools, allows: (tool) => all || tools.has(tool) };
}

/** Policy that permits every mutating tool. Intended for tests and trusted embedding. */
export const ALLOW_ALL_MUTATIONS: MutationPolicy = buildPolicy(true, new Set());

/**
 * Parses MISP_ALLOWED_MUTATIONS: a comma-separated list of tool names, or `*`
 * (also `all`) for every mutating tool. Unset or empty means read-only.
 * Unknown names are rejected so a typo cannot silently leave a tool disabled.
 */
export function parseMutationAllowlist(raw: string | undefined): MutationPolicy {
  const entries = (raw ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  if (entries.some((entry) => entry === "*" || entry.toLowerCase() === "all")) {
    return ALLOW_ALL_MUTATIONS;
  }

  const unknown = entries.filter((entry) => !MUTATING_TOOL_NAMES.includes(entry));
  if (unknown.length > 0) {
    throw new Error(
      `MISP_ALLOWED_MUTATIONS contains unknown tool name(s): ${unknown.join(", ")}. ` +
        `Valid names: ${MUTATING_TOOL_NAMES.join(", ")}.`
    );
  }

  return buildPolicy(false, new Set(entries));
}

export function createMutationPolicy(env: NodeJS.ProcessEnv = process.env): MutationPolicy {
  return parseMutationAllowlist(env.MISP_ALLOWED_MUTATIONS);
}

type GuardResult = {
  content: Array<{ type: "text"; text: string }>;
  isError: boolean;
};

function blocked(text: string): GuardResult {
  return {
    content: [{ type: "text", text }],
    isError: true,
  };
}

/**
 * Returns a blocking error result if the destructive action is not confirmed,
 * or `null` if the action is authorized to proceed.
 *
 * @param confirm  The `confirm` argument supplied by the caller.
 * @param action   Human-readable description for the error message.
 */
export function requireConfirmation(
  confirm: boolean | undefined,
  action: string
): GuardResult | null {
  if (confirm === true || destructiveEnvOptIn()) {
    return null;
  }
  return blocked(
    `Refused: ${action} is a destructive action. Pass "confirm": true to proceed, ` +
      `or set MISP_ALLOW_DESTRUCTIVE=true to pre-authorize destructive operations.`
  );
}

/**
 * Second-stage confirmation for permanent/irreversible ("hard") deletes.
 * The env opt-in does NOT bypass this; `confirmHard: true` is always required.
 *
 * @param confirmHard  The `confirmHard` argument supplied by the caller.
 * @param action       Human-readable description for the error message.
 */
export function requireHardConfirmation(
  confirmHard: boolean | undefined,
  action: string
): GuardResult | null {
  if (confirmHard === true) {
    return null;
  }
  return blocked(
    `Refused: ${action} is a PERMANENT, irreversible delete. ` +
      `Pass "confirmHard": true (in addition to "confirm": true) to proceed.`
  );
}

/**
 * Returns a blocking error result when the operator has not enabled this
 * state-changing tool, or `null` when it may run.
 */
export function requireMutationAllowed(
  policy: MutationPolicy,
  tool: string
): GuardResult | null {
  if (policy.allows(tool)) {
    return null;
  }
  return blocked(
    `Refused: ${tool} changes MISP state and is not enabled on this server. ` +
      `The operator must add "${tool}" to MISP_ALLOWED_MUTATIONS. ` +
      `Pass "dryRun": true to preview the call without changing anything.`
  );
}
