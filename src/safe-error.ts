const SECRET_PATTERNS = [
  /(authorization:\s*)[^\r\n,;]+/gi,
  /\b(basic|bearer)\s+[a-z0-9._~+/=-]+/gi,
  /([?&](?:password|token|secret|api[_-]?key|key)=)[^&\s]+/gi,
  /("(?:api[_-]?key|authorization|token|password)"\s*:\s*")([^"]+)(")/gi,
];

export function sanitizeErrorMessage(message: string, secrets: string[] = []): string {
  let sanitized = message;
  for (const secret of secrets) {
    if (secret) sanitized = sanitized.split(secret).join("[REDACTED]");
  }
  return sanitized
    .replace(SECRET_PATTERNS[0], "$1[REDACTED]")
    .replace(SECRET_PATTERNS[1], "$1 [REDACTED]")
    .replace(SECRET_PATTERNS[2], "$1[REDACTED]")
    .replace(SECRET_PATTERNS[3], "$1[REDACTED]$3")
    .slice(0, 500);
}

export function safeCaughtErrorMessage(
  error: unknown,
  fallback: string,
  secrets: string[] = [],
): string {
  if (error instanceof Error) return sanitizeErrorMessage(error.message, secrets);
  if (typeof error === "string") return sanitizeErrorMessage(error, secrets);
  return fallback;
}
