import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const installer = readFileSync("scripts/proxmox_install.sh", "utf8");
const commit = "a1".repeat(20);
const artifact = "reviewed-node-fixture";
const digest = createHash("sha256").update(artifact).digest("hex");
const pins = { MISP_SOURCE_COMMIT: commit, NODE_VERSION: "22.23.4", NODE_ARCH: "x64", NODE_SHA256: digest };
const nodeSetup = installer.match(/pct exec "\$CTID" -- env NODE_VERSION=[^\n]+ bash -ceu '([\s\S]*?)\n'/)?.[0] ?? "";
const sourceSetup = installer.match(/pct exec "\$CTID" -- env SOURCE_COMMIT=[^\n]+ bash -ceu '([\s\S]*?)\n'/)?.[0] ?? "";

function harness(code: string, overrides: Record<string, string> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "installer-pins-"));
  const trace = join(dir, "trace");
  try {
    const result = spawnSync("bash", ["-e", "-c", `
      record() { printf '%s\\n' "$*" >> "$TRACE"; }
      pct() { record "pct $1 $2"; [[ "$1" == exec && "$2" == fixture && "$3" == -- ]] || return 90; while [[ "$1" != -- ]]; do shift; done; shift; "$@"; }
      git() {
        record "git $*"
        if [[ "$1" == fetch && "$FAIL_FETCH" == yes ]]; then return 7; fi
        if [[ "$1" == rev-parse ]]; then printf '%s\\n' "$ACTUAL_COMMIT"; fi
      }
      npm() { record "npm $*"; }
      cd() { :; }
      dpkg() { printf '%s\\n' "$GUEST_ARCH"; }
      curl() {
        record "curl $*"
        [[ "$FAIL_DOWNLOAD" != yes ]] || return 8
        local target=
        while (( $# )); do
          if [[ "$1" == --output ]]; then target="$2"; shift; fi
          shift
        done
        printf '%s' "$ARTIFACT" > "$target"
      }
      tar() { record "tar $*"; }
      pvesh() { record "pvesh $*"; return 90; }
      pveam() { record "pveam $*"; return 90; }
      export -f record pct git npm cd dpkg curl tar pvesh pveam
      ${code}
    `], { env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: dir, TRACE: trace, CTID: "fixture",
      ARTIFACT: artifact, ACTUAL_COMMIT: commit, GUEST_ARCH: "amd64", FAIL_FETCH: "no", FAIL_DOWNLOAD: "no",
      ...pins, ...overrides }, encoding: "utf8", timeout: 5000 });
    let calls = "";
    try { calls = readFileSync(trace, "utf8"); } catch { /* validation may reject before any calls */ }
    return { ...result, calls };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

describe("immutable installer inputs", () => {
  it.each([
    ["MISP_SOURCE_COMMIT", ""], ["MISP_SOURCE_COMMIT", "main"],
    ["MISP_SOURCE_COMMIT", "a".repeat(39)], ["MISP_SOURCE_COMMIT", "g".repeat(40)],
    ["MISP_SOURCE_COMMIT", commit + ";id"], ["MISP_SOURCE_COMMIT", commit + "\n"],
    ["NODE_VERSION", ""], ["NODE_VERSION", "22"], ["NODE_VERSION", "20.18.0"],
    ["NODE_VERSION", "22.11.0"], ["NODE_VERSION", "22.023.4"], ["NODE_VERSION", "22.23.4;id"],
    ["NODE_VERSION", "22.23.4\n"], ["NODE_ARCH", ""], ["NODE_ARCH", "x64;id"],
    ["NODE_SHA256", ""], ["NODE_SHA256", "a".repeat(63)],
    ["NODE_SHA256", "z".repeat(64)], ["NODE_SHA256", digest + "\n"],
  ])("rejects %s=%j before any host or container command", (key, value) => {
    const result = harness(installer, { [key]: value });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(key);
    expect(result.calls).toBe("");
  });

  it("accepts exact pins and normalizes hexadecimal case before host work", () => {
    const validation = installer.slice(0, installer.indexOf("# Pre-flight"));
    const result = harness(validation + '\nprintf "%s:%s" "$MISP_SOURCE_COMMIT" "$NODE_SHA256"', {
      MISP_SOURCE_COMMIT: commit.toUpperCase(), NODE_SHA256: digest.toUpperCase(),
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`${commit}:${digest}`);
    expect(result.calls).toBe("");
  });
});

describe("official Node archive verification", () => {
  it("downloads the exact official artifact and verifies its checksum before extraction", () => {
    const result = harness(nodeSetup);
    expect(result.status, result.stderr).toBe(0);
    expect(result.calls).toContain("https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-x64.tar.xz");
    expect(result.calls).toContain("--proto =https");
    expect(result.calls).toContain("tar -xJf");
    expect(result.calls).toContain("--no-same-owner");
    expect(installer).not.toContain("deb.nodesource.com");
  });

  it.each([
    { NODE_SHA256: "b".repeat(64) }, { FAIL_DOWNLOAD: "yes" }, { GUEST_ARCH: "arm64" },
  ])("stops before extraction or npm when artifact verification fails: %j", (overrides) => {
    const result = harness(nodeSetup + "\n" + sourceSetup, overrides);
    expect(result.status).not.toBe(0);
    expect(result.calls).not.toMatch(/^tar |^npm |^git /m);
  });
});

describe("canonical reviewed source", () => {
  it("fetches the full commit from the canonical repository and verifies before npm", () => {
    const result = harness(sourceSetup);
    expect(result.status, result.stderr).toBe(0);
    expect(result.calls).toContain("git remote add origin https://github.com/lidless-labs/misp-mcp.git");
    expect(result.calls).toContain(`git fetch --depth 1 origin ${commit}`);
    expect(result.calls).toContain("git checkout --detach FETCH_HEAD");
    expect(result.calls).toContain("git rev-parse --verify HEAD^{commit}");
    expect(result.calls).toContain("npm ci --ignore-scripts");
    expect(result.calls).toContain("npm run build");
    expect(result.calls).toContain("npm prune --omit=dev --ignore-scripts");
    expect(result.calls.indexOf("git rev-parse")).toBeLessThan(result.calls.indexOf("npm ci"));
  });

  it.each([{ ACTUAL_COMMIT: "b".repeat(40) }, { FAIL_FETCH: "yes" }])(
    "stops before dependencies or build on source verification failure: %j", (overrides) => {
      const result = harness(sourceSetup, overrides);
      expect(result.status).not.toBe(0);
      expect(result.calls).not.toMatch(/^npm /m);
    });
});
