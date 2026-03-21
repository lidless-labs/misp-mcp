// MISP Event
export interface MispEvent {
  id: string;
  orgc_id: string;
  org_id: string;
  info: string;
  date: string;
  threat_level_id: string;
  analysis: string;
  distribution: string;
  published: boolean;
  uuid: string;
  timestamp: string;
  publish_timestamp: string;
  attribute_count: string;
  Orgc?: { id: string; name: string; uuid: string };
  Org?: { id: string; name: string; uuid: string };
  Tag?: MispTag[];
  Attribute?: MispAttribute[];
  Object?: MispObject[];
  Galaxy?: MispGalaxy[];
  RelatedEvent?: Array<{ Event: MispEvent }>;
}

// MISP Attribute (IOC)
export interface MispAttribute {
  id: string;
  event_id: string;
  type: string;
  category: string;
  value: string;
  to_ids: boolean;
  uuid: string;
  timestamp: string;
  distribution: string;
  comment: string;
  deleted: boolean;
  Tag?: MispTag[];
  Event?: Partial<MispEvent>;
  SharingGroup?: Record<string, unknown>;
  RelatedAttribute?: Array<{
    id: string;
    value: string;
    type: string;
    event_id: string;
  }>;
}

// MISP Object (grouped attributes)
export interface MispObject {
  id: string;
  name: string;
  meta_category: string;
  description: string;
  uuid: string;
  timestamp: string;
  distribution: string;
  event_id: string;
  Attribute?: (MispAttribute & { object_relation?: string })[];
}

// MISP Object Template
export interface MispObjectTemplate {
  id: string;
  uuid: string;
  name: string;
  description: string;
  version: string;
  meta_category: string;
  ObjectTemplateElement?: Array<{
    object_relation: string;
    type: string;
    description: string;
    ui_priority: number;
    categories: string[];
    sane_default?: string[];
    values_list?: string[];
    multiple?: boolean;
    disable_correlation?: boolean;
  }>;
}

// MISP Feed
export interface MispFeed {
  id: string;
  name: string;
  provider: string;
  url: string;
  enabled: boolean;
  source_format: string;
  distribution: string;
  event_id: string;
  caching_enabled: boolean;
}

// MISP Organisation
export interface MispOrganisation {
  id: string;
  name: string;
  uuid: string;
  description: string;
  nationality: string;
  sector: string;
  type: string;
  local: boolean;
}

// MISP Galaxy Cluster
export interface MispGalaxyCluster {
  id: string;
  uuid: string;
  type: string;
  value: string;
  tag_name: string;
  description: string;
  galaxy_id: string;
}

// MISP Sharing Group
export interface MispSharingGroup {
  id: string;
  name: string;
  description: string;
  uuid: string;
  releasability: string;
  active: boolean;
  org_count: number;
}

// MISP Server Version
export interface MispServerVersion {
  version: string;
  pymisp_recommended_version: string;
  perm_sync: boolean;
  perm_sighting: boolean;
  perm_galaxy_editor: boolean;
  perm_analyst_data: boolean;
}

// MISP Tag
export interface MispTag {
  id: string;
  name: string;
  colour: string;
  exportable: boolean;
  org_id?: string;
  numerical_value?: string;
  attribute_count?: string;
  event_count?: string;
}

// MISP Galaxy
export interface MispGalaxy {
  id: string;
  uuid: string;
  name: string;
  type: string;
  description: string;
  GalaxyCluster?: Array<{
    id: string;
    uuid: string;
    type: string;
    value: string;
    tag_name: string;
    description: string;
  }>;
}

// MISP Sighting
export interface MispSighting {
  id: string;
  attribute_id: string;
  event_id: string;
  org_id: string;
  date_sighting: string;
  source: string;
  type: string;
}

// MISP Taxonomy
export interface MispTaxonomy {
  id: string;
  namespace: string;
  description: string;
  version: string;
  enabled: boolean;
  exclusive: boolean;
  required: boolean;
}

// MISP Warninglist match
export interface MispWarninglistMatch {
  id: string;
  name: string;
  type: string;
  description: string;
  category: string;
  warninglist_entry_count: string;
}

// API response wrappers
export interface EventSearchResponse {
  response: Array<{ Event: MispEvent }>;
}

export interface AttributeSearchResponse {
  response: {
    Attribute: MispAttribute[];
  };
}

export interface EventResponse {
  Event: MispEvent;
}

export interface DescribeTypesResponse {
  result: {
    sane_defaults: Record<string, { default_category: string; to_ids: number }>;
    types: string[];
    categories: string[];
    category_type_mappings: Record<string, string[]>;
  };
}

export interface TagListResponse {
  Tag: MispTag[];
}

export interface TaxonomyListResponse {
  [index: number]: {
    Taxonomy: MispTaxonomy;
  };
}

export interface WarninglistCheckResponse {
  [value: string]: MispWarninglistMatch[];
}

export interface StatisticsResponse {
  [key: string]: string | number;
}
