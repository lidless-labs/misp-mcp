import { Agent } from "undici";
import type { MispConfig } from "./config.js";
import type {
  MispEvent,
  MispAttribute,
  MispObject,
  MispSighting,
  MispObjectTemplate,
  MispFeed,
  MispOrganisation,
  MispGalaxyCluster,
  MispSharingGroup,
  MispServerVersion,
  EventSearchResponse,
  AttributeSearchResponse,
  EventResponse,
  DescribeTypesResponse,
  TagListResponse,
  WarninglistCheckResponse,
  StatisticsResponse,
} from "./types.js";

// Allow numeric IDs or UUIDs (and any combination of [A-Za-z0-9_-]). Reject
// anything that could alter the URL path (slashes, query/fragment chars, etc).
const ID_PATTERN = /^[A-Za-z0-9_-]+$/;
function encodeId(id: string, kind = "id"): string {
  if (!ID_PATTERN.test(id)) {
    throw new Error(`Invalid ${kind}: ${JSON.stringify(id)}`);
  }
  return encodeURIComponent(id);
}

export class MispClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;
  private dispatcher: Agent;

  constructor(config: MispConfig) {
    this.baseUrl = config.url;
    this.apiKey = config.apiKey;
    this.timeout = config.timeout;
    this.dispatcher = new Agent({
      connect: { rejectUnauthorized: config.verifySsl },
    });
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    rawResponse?: false
  ): Promise<T>;
  private async request(
    method: string,
    path: string,
    body: unknown,
    rawResponse: true
  ): Promise<string>;
  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    rawResponse = false
  ): Promise<T | string> {
    const url = `${this.baseUrl}${path}`;

    const headers: Record<string, string> = {
      Authorization: this.apiKey,
      Accept: "application/json",
      "Content-Type": "application/json",
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const options: RequestInit & { dispatcher?: unknown } = {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      dispatcher: this.dispatcher,
    };

    let response: Response;
    try {
      response = await fetch(url, options);
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new Error(`MISP API timeout after ${this.timeout}ms`);
      }
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`MISP API request failed: ${message}`);
    } finally {
      clearTimeout(timeoutId);
    }

    const text = await response.text();

    if (!response.ok) {
      const statusMessages: Record<number, string> = {
        401: "Invalid API key or unauthorized",
        403: "Insufficient permissions",
        404: "Resource not found",
        405: "Method not allowed",
      };

      const prefix = statusMessages[response.status] || `HTTP ${response.status}`;
      let detail = "";
      try {
        const parsed = JSON.parse(text);
        detail = parsed.message || parsed.errors || text;
      } catch {
        detail = text;
      }
      throw new Error(`${prefix}: ${detail}`);
    }

    if (rawResponse) {
      return text;
    }

    try {
      return JSON.parse(text) as T;
    } catch {
      throw new Error(`Failed to parse MISP response as JSON: ${text.slice(0, 200)}`);
    }
  }

  // --- Event methods ---

  async searchEvents(params: {
    value?: string;
    type?: string;
    category?: string;
    tags?: string[];
    eventid?: string;
    org?: string;
    dateFrom?: string;
    dateTo?: string;
    last?: string;
    published?: boolean;
    limit?: number;
    page?: number;
  }): Promise<MispEvent[]> {
    const body: Record<string, unknown> = {
      returnFormat: "json",
      limit: params.limit ?? 50,
    };

    if (params.value) body.value = params.value;
    if (params.type) body.type = params.type;
    if (params.category) body.category = params.category;
    if (params.tags) body.tags = params.tags;
    if (params.eventid) body.eventid = params.eventid;
    if (params.org) body.org = params.org;
    if (params.dateFrom) body.from = params.dateFrom;
    if (params.dateTo) body.to = params.dateTo;
    if (params.last) body.last = params.last;
    if (params.published !== undefined) body.published = params.published ? 1 : 0;
    if (params.page) body.page = params.page;

    const data = await this.request<EventSearchResponse>(
      "POST",
      "/events/restSearch",
      body
    );
    return (data.response || []).map((r) => r.Event);
  }

  async getEvent(eventId: string): Promise<MispEvent> {
    const data = await this.request<EventResponse>(
      "GET",
      `/events/view/${encodeId(eventId, "eventId")}`
    );
    return data.Event;
  }

  async createEvent(params: {
    info: string;
    distribution: number;
    threat_level_id: number;
    analysis: number;
    date?: string;
    tags?: string[];
  }): Promise<MispEvent> {
    const eventData: Record<string, unknown> = {
      info: params.info,
      distribution: params.distribution,
      threat_level_id: params.threat_level_id,
      analysis: params.analysis,
    };

    if (params.date) eventData.date = params.date;

    const data = await this.request<EventResponse>("POST", "/events/add", {
      Event: eventData,
    });

    // Add tags after creation if specified
    if (params.tags && params.tags.length > 0 && data.Event.id) {
      for (const tag of params.tags) {
        await this.tagEvent(data.Event.id, tag);
      }
      // Re-fetch to include tags
      return this.getEvent(data.Event.id);
    }

    return data.Event;
  }

  async updateEvent(
    eventId: string,
    params: {
      info?: string;
      threat_level_id?: number;
      analysis?: number;
    }
  ): Promise<MispEvent> {
    const eventData: Record<string, unknown> = {};
    if (params.info !== undefined) eventData.info = params.info;
    if (params.threat_level_id !== undefined)
      eventData.threat_level_id = params.threat_level_id;
    if (params.analysis !== undefined) eventData.analysis = params.analysis;

    const data = await this.request<EventResponse>(
      "POST",
      `/events/edit/${encodeId(eventId, "eventId")}`,
      { Event: eventData }
    );
    return data.Event;
  }

  async publishEvent(eventId: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      "POST",
      `/events/publish/${encodeId(eventId, "eventId")}`
    );
  }

  async tagEvent(eventId: string, tag: string): Promise<unknown> {
    return this.request("POST", "/events/addTag", {
      event: eventId,
      tag,
    });
  }

  async untagEvent(eventId: string, tag: string): Promise<unknown> {
    return this.request("POST", "/events/removeTag", {
      event: eventId,
      tag,
    });
  }

  // --- Attribute methods ---

  async searchAttributes(params: {
    value?: string;
    type?: string;
    category?: string;
    tags?: string[];
    to_ids?: boolean;
    includeCorrelations?: boolean;
    last?: string;
    limit?: number;
  }): Promise<MispAttribute[]> {
    const body: Record<string, unknown> = {
      returnFormat: "json",
      limit: params.limit ?? 50,
    };

    if (params.value) body.value = params.value;
    if (params.type) body.type = params.type;
    if (params.category) body.category = params.category;
    if (params.tags) body.tags = params.tags;
    if (params.to_ids !== undefined) body.to_ids = params.to_ids ? 1 : 0;
    if (params.includeCorrelations)
      body.includeCorrelations = 1;
    if (params.last) body.last = params.last;

    const data = await this.request<AttributeSearchResponse>(
      "POST",
      "/attributes/restSearch",
      body
    );
    return data.response?.Attribute || [];
  }

  async addAttribute(
    eventId: string,
    params: {
      type: string;
      value: string;
      category?: string;
      to_ids?: boolean;
      comment?: string;
      distribution?: number;
      tags?: string[];
    }
  ): Promise<MispAttribute> {
    const attrData: Record<string, unknown> = {
      type: params.type,
      value: params.value,
    };

    if (params.category) attrData.category = params.category;
    if (params.to_ids !== undefined) attrData.to_ids = params.to_ids;
    if (params.comment) attrData.comment = params.comment;
    if (params.distribution !== undefined)
      attrData.distribution = params.distribution;

    const data = await this.request<{ Attribute: MispAttribute }>(
      "POST",
      `/attributes/add/${encodeId(eventId, "eventId")}`,
      attrData
    );

    // Add tags if specified
    if (params.tags && params.tags.length > 0 && data.Attribute?.id) {
      for (const tag of params.tags) {
        await this.request("POST", "/attributes/addTag", {
          attribute: data.Attribute.id,
          tag,
        });
      }
    }

    return data.Attribute;
  }

  async deleteAttribute(
    attributeId: string,
    hard = false
  ): Promise<{ message: string }> {
    const body = hard ? { hard: 1 } : {};
    return this.request<{ message: string }>(
      "POST",
      `/attributes/delete/${encodeId(attributeId, "attributeId")}`,
      body
    );
  }

  // --- Describe types ---

  async describeTypes(): Promise<DescribeTypesResponse["result"]> {
    const data = await this.request<DescribeTypesResponse>(
      "GET",
      "/attributes/describeTypes"
    );
    return data.result;
  }

  // --- Tags ---

  async listTags(search?: string): Promise<MispTag[]> {
    const path = search
      ? `/tags/search/${encodeURIComponent(search)}`
      : "/tags";
    const data = await this.request<TagListResponse>("GET", path);
    return data.Tag || [];
  }

  // --- Sightings ---

  async addSighting(params: {
    attributeId?: string;
    value?: string;
    type: number;
    source?: string;
    timestamp?: string;
  }): Promise<MispSighting> {
    const body: Record<string, unknown> = {
      type: params.type,
    };

    if (params.value) body.value = params.value;
    if (params.source) body.source = params.source;
    if (params.timestamp) body.timestamp = params.timestamp;

    const path = params.attributeId
      ? `/sightings/add/${encodeId(params.attributeId, "attributeId")}`
      : "/sightings/add";

    const data = await this.request<{ Sighting: MispSighting }>("POST", path, body);
    return data.Sighting;
  }

  // --- Warninglists ---

  async checkWarninglists(value: string): Promise<WarninglistCheckResponse> {
    return this.request<WarninglistCheckResponse>(
      "POST",
      "/warninglists/checkValue",
      [value]
    );
  }

  // --- Statistics ---

  async getStatistics(): Promise<StatisticsResponse> {
    return this.request<StatisticsResponse>("GET", "/events/index");
  }

  // --- Taxonomies ---

  async listTaxonomies(): Promise<
    Array<{ namespace: string; description: string; version: string; enabled: boolean }>
  > {
    const data = await this.request<
      Array<{ Taxonomy: { namespace: string; description: string; version: string; enabled: boolean } }>
    >("GET", "/taxonomies");
    return (data || []).map((t) => t.Taxonomy);
  }

  // --- Exports ---

  async exportEvents(params: {
    eventId?: string;
    format: string;
    type?: string;
    tags?: string[];
    last?: string;
  }): Promise<string> {
    const formatEndpoints: Record<string, string> = {
      csv: "/events/csv/download",
      stix: "/events/stix/download",
      suricata: "/events/nids/suricata/download",
      snort: "/events/nids/snort/download",
      text: "/attributes/text/download",
      rpz: "/attributes/rpz/download",
    };

    const endpoint = formatEndpoints[params.format];
    if (!endpoint) {
      throw new Error(
        `Unsupported export format: ${params.format}. Supported: ${Object.keys(formatEndpoints).join(", ")}`
      );
    }

    const body: Record<string, unknown> = {};
    if (params.eventId) body.eventid = params.eventId;
    if (params.type) body.type = params.type;
    if (params.tags) body.tags = params.tags;
    if (params.last) body.last = params.last;

    return this.request("POST", endpoint, body, true);
  }

  async exportHashes(params: {
    format: string;
    last?: string;
    tags?: string[];
  }): Promise<string> {
    const validFormats = ["md5", "sha1", "sha256"];
    if (!validFormats.includes(params.format)) {
      throw new Error(
        `Unsupported hash format: ${params.format}. Supported: ${validFormats.join(", ")}`
      );
    }

    let path = `/events/hids/${params.format}/download`;
    const queryParts: string[] = [];
    if (params.last) queryParts.push(`last=${encodeURIComponent(params.last)}`);
    if (params.tags) queryParts.push(`tags=${encodeURIComponent(params.tags.join(","))}`);
    if (queryParts.length > 0) path += `?${queryParts.join("&")}`;

    return this.request("GET", path, undefined, true);
  }

  // --- Objects ---

  async listObjectTemplates(): Promise<MispObjectTemplate[]> {
    const data = await this.request<
      Array<{ ObjectTemplate: MispObjectTemplate }>
    >("GET", "/objectTemplates");
    return (data || []).map((t) => t.ObjectTemplate);
  }

  async getObjectTemplate(templateId: string): Promise<MispObjectTemplate> {
    const data = await this.request<{ ObjectTemplate: MispObjectTemplate }>(
      "GET",
      `/objectTemplates/view/${encodeId(templateId, "templateId")}`
    );
    return data.ObjectTemplate;
  }

  async addObject(
    eventId: string,
    params: {
      name: string;
      attributes: Array<{
        object_relation: string;
        type: string;
        value: string;
        to_ids?: boolean;
        comment?: string;
      }>;
      comment?: string;
      distribution?: number;
    }
  ): Promise<MispObject> {
    const body: Record<string, unknown> = {
      name: params.name,
      Attribute: params.attributes.map((a) => ({
        object_relation: a.object_relation,
        type: a.type,
        value: a.value,
        to_ids: a.to_ids ?? false,
        comment: a.comment,
      })),
    };

    if (params.comment) body.comment = params.comment;
    if (params.distribution !== undefined)
      body.distribution = params.distribution;

    const data = await this.request<{ Object: MispObject }>(
      "POST",
      `/objects/add/${encodeId(eventId, "eventId")}`,
      body
    );
    return data.Object;
  }

  async deleteObject(
    objectId: string,
    hard = false
  ): Promise<{ message: string }> {
    const body = hard ? { hard: 1 } : {};
    return this.request<{ message: string }>(
      "POST",
      `/objects/delete/${encodeId(objectId, "objectId")}`,
      body
    );
  }

  // --- Galaxies ---

  async listGalaxies(): Promise<
    Array<{ id: string; name: string; type: string; description: string; uuid: string }>
  > {
    const data = await this.request<
      Array<{ Galaxy: { id: string; name: string; type: string; description: string; uuid: string } }>
    >("GET", "/galaxies");
    return (data || []).map((g) => g.Galaxy);
  }

  async getGalaxy(galaxyId: string): Promise<{
    id: string;
    uuid: string;
    name: string;
    type: string;
    description: string;
    GalaxyCluster?: MispGalaxyCluster[];
  }> {
    const data = await this.request<{
      Galaxy: { id: string; uuid: string; name: string; type: string; description: string };
      GalaxyCluster?: MispGalaxyCluster[];
    }>("GET", `/galaxies/view/${encodeId(galaxyId, "galaxyId")}`);

    return {
      ...data.Galaxy,
      GalaxyCluster: data.GalaxyCluster,
    };
  }

  async searchGalaxyClusters(
    search: string,
    galaxyType?: string
  ): Promise<MispGalaxyCluster[]> {
    const body: Record<string, unknown> = {
      searchall: search,
    };
    if (galaxyType) body.context = galaxyType;

    const data = await this.request<
      Array<{ GalaxyCluster: MispGalaxyCluster }>
    >("POST", "/galaxy_clusters/restSearch", body);
    return (data || []).map((c) => c.GalaxyCluster);
  }

  async attachGalaxyCluster(
    targetType: "event" | "attribute",
    targetId: string,
    galaxyClusterId: string
  ): Promise<unknown> {
    if (!ID_PATTERN.test(galaxyClusterId)) {
      throw new Error(`Invalid galaxyClusterId: ${JSON.stringify(galaxyClusterId)}`);
    }
    return this.request(
      "POST",
      `/galaxies/attachCluster/${encodeId(targetId, "targetId")}/${targetType}`,
      { Galaxy: { target_id: galaxyClusterId } }
    );
  }

  // --- Feeds ---

  async listFeeds(): Promise<MispFeed[]> {
    const data = await this.request<Array<{ Feed: MispFeed }>>(
      "GET",
      "/feeds"
    );
    return (data || []).map((f) => f.Feed);
  }

  async toggleFeed(
    feedId: string,
    enable: boolean
  ): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      "POST",
      `/feeds/${enable ? "enable" : "disable"}/${encodeId(feedId, "feedId")}`
    );
  }

  async fetchFeed(feedId: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      "GET",
      `/feeds/fetchFromFeed/${encodeId(feedId, "feedId")}`
    );
  }

  async cacheFeed(feedId: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      "GET",
      `/feeds/cacheFeeds/${encodeId(feedId, "feedId")}`
    );
  }

  // --- Organisations ---

  async listOrganisations(
    scope: "local" | "external" | "all" = "all"
  ): Promise<MispOrganisation[]> {
    // scope is constrained by the TS type above
    const data = await this.request<
      Array<{ Organisation: MispOrganisation }>
    >("GET", `/organisations/index/scope:${scope}`);
    return (data || []).map((o) => o.Organisation);
  }

  async getOrganisation(orgId: string): Promise<MispOrganisation> {
    const data = await this.request<{ Organisation: MispOrganisation }>(
      "GET",
      `/organisations/view/${encodeId(orgId, "orgId")}`
    );
    return data.Organisation;
  }

  // --- Server ---

  async getVersion(): Promise<MispServerVersion> {
    return this.request<MispServerVersion>("GET", "/servers/getVersion");
  }

  async getServerSettings(): Promise<{ diagnostics?: unknown }> {
    try {
      return await this.request<{ diagnostics?: unknown }>(
        "GET",
        "/servers/serverSettings"
      );
    } catch (err) {
      // serverSettings requires site-admin. If the token lacks that permission
      // MISP returns 403; surface everything else so real failures aren't masked.
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.startsWith("Insufficient permissions") || msg.startsWith("HTTP 403")) {
        return {};
      }
      throw err;
    }
  }

  async listSharingGroups(): Promise<MispSharingGroup[]> {
    const data = await this.request<{
      response: Array<{ SharingGroup: MispSharingGroup }>;
    }>("GET", "/sharing_groups");
    return (data.response || []).map((g) => g.SharingGroup);
  }

  async deleteEvent(eventId: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      "POST",
      `/events/delete/${encodeId(eventId, "eventId")}`
    );
  }
}

// Re-export the tag type used above
import type { MispTag } from "./types.js";
