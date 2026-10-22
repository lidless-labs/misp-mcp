/**
 * Shared parser for boolean environment flags.
 *
 * Accepted values, case-insensitive after trimming: true, 1, false, 0.
 * Unset, empty, and whitespace-only values mean the default. Anything else
 * throws an error that names the variable, so a mistyped safety flag stops the
 * process instead of silently picking a side.
 */
export function parseBooleanEnv(
  name: string,
  raw: string | undefined,
  defaultValue: boolean
): boolean {
  const value = raw?.trim().toLowerCase();
  if (value === undefined || value === "") return defaultValue;
  if (value === "true" || value === "1") return true;
  if (value === "false" || value === "0") return false;
  throw new Error(
    `${name} must be one of true, false, 1, or 0 (case-insensitive); got ${JSON.stringify(raw)}`
  );
}
