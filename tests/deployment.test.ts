import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const installer = readFileSync(new URL("../scripts/proxmox_install.sh", import.meta.url), "utf8");
const dockerfile = readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");

describe("deployment privilege boundaries", () => {
  it("runs the final image as nonroot without giving it ownership of the application", () => {
    const runtime = dockerfile.split(/^FROM /m).at(-1)!;
    const user = runtime.match(/^USER\s+(\S+)/m)?.[1];
    expect(user).toBeDefined();
    expect(user).not.toMatch(/^(root|0)(:|$)/);
    expect(runtime).not.toMatch(/(?:chown|--chown)[^\n]*(?:\/app|dist|node_modules)/);
    expect(runtime).toMatch(/chmod\s+-R\s+(?:a-w|go-w)\s+\/app/);
  });

  it("sandboxes the service with a writable runtime directory and private temporary files", () => {
    const unit = installer.match(/\[Unit\][\s\S]*?WantedBy=multi-user.target/)![0];
    const settings = Object.fromEntries(unit.split("\n").filter(line => line.includes("=")).map(line => {
      const equals = line.indexOf("=");
      return [line.slice(0, equals), line.slice(equals + 1)];
    }));
    expect(settings.User).toBe("misp-mcp");
    expect(settings.Group).toBe("misp-mcp");
    expect(settings.ProtectSystem).toBe("strict");
    expect(settings.ProtectHome).toBe("true");
    expect(settings.NoNewPrivileges).toBe("true");
    expect(settings.CapabilityBoundingSet).toBe("");
    expect(settings.RuntimeDirectory).toBe("misp-mcp");
    expect(settings.RuntimeDirectoryMode).toBe("0700");
    expect(settings.ReadWritePaths).toBeUndefined();
    expect(settings.EnvironmentFile).toBe("/etc/misp-mcp/environment");
    expect(installer).toMatch(/useradd[^\n]*--system[^\n]*--no-create-home[^\n]*--shell \/usr\/sbin\/nologin/);
    expect(installer).toMatch(/chown -R root:root \/opt\/misp-mcp/);
    expect(installer).toMatch(/chmod -R go-w \/opt\/misp-mcp/);
  });

  it("streams quoted credentials over stdin instead of interpolating them into commands", () => {
    const setup = installer.match(/^# Configure service\n([\s\S]*?)^# Systemd service/m)![1];
    const result = execFileSync("bash", ["-eu", "-c", `
      pct() {
        for arg in "$@"; do
          case "$arg" in *"$MISP_API_KEY_VAL"*) exit 91;; esac
        done
        case "$*" in *"/etc/misp-mcp/environment"*) cat;; esac
      }
      ${setup}
    `], {
      env: { ...process.env, CTID: "100", MCP_PORT: "3101", MISP_URL_VAL: "https://misp.example.com", MISP_API_KEY_VAL: `key'\"\\$HOME\`id\`$(echo injected)` },
      encoding: "utf8",
    });
    expect(result).toBe('MISP_URL="https://misp.example.com"\nMISP_API_KEY="key\'\\"\\\\$HOME`id`$(echo injected)"\nPORT="3101"\n');
    expect(setup).toMatch(/install -d -o root -g root -m 0700 \/etc\/misp-mcp/);
    expect(setup).toMatch(/umask 077/);
    expect(setup).toMatch(/chmod 600 \/etc\/misp-mcp\/environment/);
  });
});

it("pins both Docker stages to the same reviewed official Node 22 slim digest", () => {
  const bases = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map(match => match[1]);
  expect(bases).toHaveLength(2);
  expect(bases[0]).toMatch(/^node:22(?:\.[0-9]+\.[0-9]+)?-(?:bookworm-)?slim@sha256:[a-f0-9]{64}$/);
  expect(bases[1]).toBe(bases[0]);
});
