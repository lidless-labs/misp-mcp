/**
 * Safety guards for destructive / state-changing MISP tools.
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

/** True when destructive actions are pre-authorized via environment. */
export function destructiveEnvOptIn(): boolean {
  return process.env.MISP_ALLOW_DESTRUCTIVE === "true";
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
