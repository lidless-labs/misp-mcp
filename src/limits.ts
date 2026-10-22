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
