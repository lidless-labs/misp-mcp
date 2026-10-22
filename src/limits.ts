import { z } from "zod";

/**
 * Upper bounds for inputs that fan out into many MISP requests or writes.
 * Schemas reject values above these maxima; they are not configuration.
 */

/** Attributes accepted by one misp_add_attributes_bulk call. */
export const BULK_MAX_ATTRIBUTES = 100;

/** Bulk writes above this many attributes need confirm:true (a dryRun preview never does). */
export const BULK_CONFIRM_THRESHOLD = 10;

/** A bulk write stops after this many failures in a row and reports the rest as skipped. */
export const BULK_MAX_CONSECUTIVE_FAILURES = 5;

/** Attributes accepted inside one MISP object. */
export const OBJECT_MAX_ATTRIBUTES = 100;

/** Tags applied by one create-event or add-attribute call (each tag is a request). */
export const MAX_TAGS_PER_CALL = 20;

/** misp_get_related_events: attributes to correlate, one MISP search request each. */
export const CORRELATION_MAX_ATTRIBUTES = 50;

/** misp_get_related_events: matches fetched per attribute. */
export const CORRELATION_MAX_PER_ATTRIBUTE = 500;

/** Default and maximum page size for search tools. */
export const DEFAULT_SEARCH_LIMIT = 50;
export const SEARCH_LIMIT_MAX = 500;

/** Integer page size, 1 to SEARCH_LIMIT_MAX. */
export function limitInput(description = `Max results (default ${DEFAULT_SEARCH_LIMIT}, max ${SEARCH_LIMIT_MAX})`) {
  return z.number().int().min(1).max(SEARCH_LIMIT_MAX).optional().describe(description);
}

/** Integer page number starting at 1. */
export function pageInput(description = "Page number for pagination (starts at 1)") {
  return z.number().int().min(1).optional().describe(description);
}

/**
 * Trailing note for a search result, or undefined when the page was not full.
 * A full page means more results may exist.
 */
export function moreResultsNote(returned: number, limit: number | undefined, page: number | undefined): string | undefined {
  const effectiveLimit = limit ?? DEFAULT_SEARCH_LIMIT;
  if (returned < effectiveLimit) return undefined;
  const nextPage = (page ?? 1) + 1;
  return `Note: this page returned ${returned} results (the limit), so more results may exist. Call again with page: ${nextPage} to continue.`;
}
