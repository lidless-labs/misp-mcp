/**
 * Static behavior declarations for every MCP tool. One table keeps the
 * annotations, the mutation allowlist, and the tests in agreement.
 *
 * - `mutating: false` tools only read from MISP.
 * - `mutating: true` tools change MISP state and run behind the mutation gate
 *   (see guards.ts). `destructive` marks tools that can delete or overwrite
 *   existing data; `idempotent` marks tools where repeating a call with the
 *   same arguments has no additional effect.
 * - `openWorld` is false only for tools that return static schema metadata.
 */
export type ToolSpec =
  | { mutating: false; openWorld?: boolean }
  | { mutating: true; destructive: boolean; idempotent: boolean; openWorld?: boolean };

export const TOOL_SPECS: Readonly<Record<string, ToolSpec>> = {
  // Events
  misp_search_events: { mutating: false },
  misp_get_event: { mutating: false },
  misp_create_event: { mutating: true, destructive: false, idempotent: false },
  misp_update_event: { mutating: true, destructive: true, idempotent: true },
  misp_publish_event: { mutating: true, destructive: true, idempotent: true },
  misp_tag_event: { mutating: true, destructive: true, idempotent: true },
  misp_delete_event: { mutating: true, destructive: true, idempotent: true },

  // Attributes
  misp_search_attributes: { mutating: false },
  misp_add_attribute: { mutating: true, destructive: false, idempotent: false },
  misp_add_attributes_bulk: { mutating: true, destructive: false, idempotent: false },
  misp_delete_attribute: { mutating: true, destructive: true, idempotent: true },

  // Correlation and intelligence
  misp_correlate: { mutating: false },
  misp_get_related_events: { mutating: false },
  misp_describe_types: { mutating: false, openWorld: false },

  // Tags
  misp_list_tags: { mutating: false },
  misp_search_by_tag: { mutating: false },

  // Exports
  misp_export_iocs: { mutating: false },
  misp_export_hashes: { mutating: false },

  // Sightings and warninglists
  misp_add_sighting: { mutating: true, destructive: true, idempotent: false },
  misp_check_warninglists: { mutating: false },

  // Objects
  misp_list_object_templates: { mutating: false, openWorld: false },
  misp_get_object_template: { mutating: false, openWorld: false },
  misp_add_object: { mutating: true, destructive: false, idempotent: false },
  misp_delete_object: { mutating: true, destructive: true, idempotent: true },

  // Galaxies
  misp_list_galaxies: { mutating: false },
  misp_get_galaxy: { mutating: false },
  misp_search_galaxy_clusters: { mutating: false },
  misp_attach_galaxy_cluster: { mutating: true, destructive: false, idempotent: true },

  // Feeds
  misp_list_feeds: { mutating: false },
  misp_toggle_feed: { mutating: true, destructive: true, idempotent: true },
  misp_fetch_feed: { mutating: true, destructive: false, idempotent: false },
  misp_cache_feed: { mutating: true, destructive: false, idempotent: true },

  // Organisations
  misp_list_organisations: { mutating: false },
  misp_get_organisation: { mutating: false },

  // Server
  misp_server_status: { mutating: false },
  misp_list_sharing_groups: { mutating: false },
};

export const MUTATING_TOOL_NAMES: readonly string[] = Object.entries(TOOL_SPECS)
  .filter(([, spec]) => spec.mutating)
  .map(([name]) => name);
