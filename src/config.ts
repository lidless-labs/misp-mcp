import { parseBooleanEnv } from "./env.js";
import { destructiveEnvOptIn } from "./guards.js";

/** Maximum allowed MISP_TIMEOUT value in seconds (1 hour). */
export const MISP_TIMEOUT_MAX_SECONDS = 3600;

const MISP_TIMEOUT_DEFAULT_SECONDS = 30;

/** Default and allowed range for MISP_MAX_RESPONSE_BYTES. */
export const MISP_MAX_RESPONSE_BYTES_DEFAULT = 16 * 1024 * 1024;
export const MISP_MAX_RESPONSE_BYTES_MIN = 1024;
export const MISP_MAX_RESPONSE_BYTES_MAX = 256 * 1024 * 1024;

export interface MispConfig {
  url: string;
  apiKey: string;
  verifySsl: boolean;
  timeout: number;
  /** Strict cap on a single response body. Defaults to MISP_MAX_RESPONSE_BYTES_DEFAULT. */
  maxResponseBytes?: number;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Validates MISP_URL and returns it without a trailing slash. HTTPS is
 * required; plain HTTP is accepted only for loopback hosts. Credentials, query
 * strings, fragments, and other schemes are rejected. Error messages never
 * echo the value, since it may contain credentials.
 */
export function parseBaseUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("MISP_URL must be an absolute URL such as https://misp.example.com");
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("MISP_URL must use https (http is allowed only for localhost)");
  }
  if (parsed.protocol === "http:" && !LOOPBACK_HOSTS.has(parsed.hostname)) {
    throw new Error(
      "MISP_URL must use https; plain http is allowed only for localhost, 127.0.0.1, or [::1]"
    );
  }
  if (parsed.username || parsed.password) {
    throw new Error("MISP_URL must not contain credentials; set MISP_API_KEY instead");
  }
  if (parsed.search || parsed.hash || raw.includes("?") || raw.includes("#")) {
    throw new Error("MISP_URL must not contain a query string or fragment");
  }

  return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, "");
}

export function parseMaxResponseBytes(raw: string | undefined): number {
  if (raw === undefined) return MISP_MAX_RESPONSE_BYTES_DEFAULT;

  const range = `between ${MISP_MAX_RESPONSE_BYTES_MIN} and ${MISP_MAX_RESPONSE_BYTES_MAX} bytes`;
  if (!/^[1-9]\d*$/.test(raw)) {
    throw new Error(
      `MISP_MAX_RESPONSE_BYTES must be a positive integer ${range} (got ${JSON.stringify(raw)})`
    );
  }
  const bytes = Number(raw);
  if (bytes < MISP_MAX_RESPONSE_BYTES_MIN || bytes > MISP_MAX_RESPONSE_BYTES_MAX) {
    throw new Error(`MISP_MAX_RESPONSE_BYTES must be ${range} (got ${bytes})`);
  }
  return bytes;
}

export function parseTimeoutSeconds(raw: string | undefined): number {
  const value = raw ?? String(MISP_TIMEOUT_DEFAULT_SECONDS);

  if (!/^[1-9]\d*$/.test(value)) {
    throw new Error(
      `MISP_TIMEOUT must be a positive integer between 1 and ${MISP_TIMEOUT_MAX_SECONDS} seconds (got ${JSON.stringify(raw ?? "")})`,
    );
  }

  const seconds = Number(value);
  if (seconds > MISP_TIMEOUT_MAX_SECONDS) {
    throw new Error(
      `MISP_TIMEOUT must be a positive integer between 1 and ${MISP_TIMEOUT_MAX_SECONDS} seconds (got ${seconds})`,
    );
  }

  return seconds;
}

export function getConfig(): MispConfig {
  const url = process.env.MISP_URL;
  if (!url) {
    throw new Error("MISP_URL environment variable is required");
  }

  const apiKey = process.env.MISP_API_KEY;
  if (!apiKey) {
    throw new Error("MISP_API_KEY environment variable is required");
  }

  const verifySsl = parseBooleanEnv("MISP_VERIFY_SSL", process.env.MISP_VERIFY_SSL, true);
  // Validate at startup so a mistyped safety flag stops the process.
  destructiveEnvOptIn();
  const timeout = parseTimeoutSeconds(process.env.MISP_TIMEOUT) * 1000;

  return {
    url: parseBaseUrl(url),
    apiKey,
    verifySsl,
    timeout,
    maxResponseBytes: parseMaxResponseBytes(process.env.MISP_MAX_RESPONSE_BYTES),
  };
}
