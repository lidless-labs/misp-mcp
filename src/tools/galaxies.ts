import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MispClient } from "../client.js";

export function registerGalaxyTools(server: McpServer, client: MispClient): void {
  // List galaxies
  server.tool(
    "misp_list_galaxies",
    "List available MISP galaxies (MITRE ATT&CK, threat actors, malware families, tools, etc.)",
    {
      search: z
        .string()
        .optional()
        .describe("Filter galaxies by name or type"),
      namespace: z
        .string()
        .optional()
        .describe(
          "Filter by namespace (e.g., mitre-attack-pattern, mitre-intrusion-set, mitre-malware)"
        ),
    },
    async ({ search, namespace }) => {
      try {
        const galaxies = await client.listGalaxies();
        let filtered = galaxies;

        if (search) {
          const q = search.toLowerCase();
          filtered = filtered.filter(
            (g) =>
              g.name.toLowerCase().includes(q) ||
              g.type.toLowerCase().includes(q) ||
              g.description.toLowerCase().includes(q)
          );
        }

        if (namespace) {
          const ns = namespace.toLowerCase();
          filtered = filtered.filter((g) =>
            g.type.toLowerCase().includes(ns)
          );
        }

        if (filtered.length === 0) {
          return {
            content: [{ type: "text", text: "No galaxies found matching the criteria." }],
          };
        }

        const summary = filtered.map((g) => ({
          id: g.id,
          name: g.name,
          type: g.type,
          description:
            g.description.length > 150
              ? g.description.slice(0, 150) + "..."
              : g.description,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error listing galaxies: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Get galaxy clusters
  server.tool(
    "misp_get_galaxy",
    "Get a specific galaxy with its clusters (e.g., MITRE ATT&CK techniques, threat actor profiles)",
    {
      galaxyId: z.string().describe("Galaxy ID to retrieve"),
    },
    async ({ galaxyId }) => {
      try {
        const galaxy = await client.getGalaxy(galaxyId);

        const result = {
          id: galaxy.id,
          uuid: galaxy.uuid,
          name: galaxy.name,
          type: galaxy.type,
          description: galaxy.description,
          clusters: (galaxy.GalaxyCluster || []).map((c) => ({
            id: c.id,
            value: c.value,
            description:
              c.description && c.description.length > 200
                ? c.description.slice(0, 200) + "..."
                : c.description,
            tag_name: c.tag_name,
          })),
          cluster_count: (galaxy.GalaxyCluster || []).length,
        };

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error getting galaxy: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Search galaxy clusters
  server.tool(
    "misp_search_galaxy_clusters",
    "Search galaxy clusters by keyword (find specific MITRE ATT&CK techniques, threat actors, malware, etc.)",
    {
      search: z
        .string()
        .describe(
          "Search term (e.g., 'phishing', 'APT28', 'ransomware', 'T1566')"
        ),
      galaxyType: z
        .string()
        .optional()
        .describe(
          "Limit to a specific galaxy type (e.g., mitre-attack-pattern, mitre-intrusion-set)"
        ),
    },
    async ({ search, galaxyType }) => {
      try {
        const results = await client.searchGalaxyClusters(search, galaxyType);

        if (results.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No galaxy clusters found matching "${search}".`,
              },
            ],
          };
        }

        const summary = results.map((c) => ({
          id: c.id,
          galaxy_id: c.galaxy_id,
          value: c.value,
          description:
            c.description && c.description.length > 200
              ? c.description.slice(0, 200) + "..."
              : c.description,
          tag_name: c.tag_name,
          type: c.type,
        }));

        return {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error searching galaxy clusters: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Attach galaxy cluster to event
  server.tool(
    "misp_attach_galaxy_cluster",
    "Attach a galaxy cluster (MITRE ATT&CK technique, threat actor, etc.) to an event or attribute",
    {
      targetType: z
        .enum(["event", "attribute"])
        .describe("Attach to an event or attribute"),
      targetId: z.string().describe("Event ID or attribute ID"),
      galaxyClusterId: z
        .string()
        .describe("Galaxy cluster ID to attach"),
    },
    async ({ targetType, targetId, galaxyClusterId }) => {
      try {
        await client.attachGalaxyCluster(targetType, targetId, galaxyClusterId);
        return {
          content: [
            {
              type: "text",
              text: `Galaxy cluster ${galaxyClusterId} attached to ${targetType} ${targetId}.`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Error attaching galaxy cluster: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
          isError: true,
        };
      }
    }
  );
}
