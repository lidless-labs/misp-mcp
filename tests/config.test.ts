import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getConfig } from "../src/config.js";

const REQUIRED_ENV = {
  MISP_URL: "https://misp.example.com",
  MISP_API_KEY: "test-api-key",
} as const;

describe("getConfig MISP_TIMEOUT", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, ...REQUIRED_ENV };
    delete process.env.MISP_TIMEOUT;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("defaults to 30 seconds when MISP_TIMEOUT is unset", () => {
    expect(getConfig().timeout).toBe(30_000);
  });

  it("accepts a positive integer within the documented maximum", () => {
    process.env.MISP_TIMEOUT = "120";
    expect(getConfig().timeout).toBe(120_000);
  });

  it("accepts the documented maximum of 3600 seconds", () => {
    process.env.MISP_TIMEOUT = "3600";
    expect(getConfig().timeout).toBe(3_600_000);
  });

  it.each([
    ["abc"],
    ["0"],
    ["-5"],
    ["30seconds"],
    ["30.5"],
    [""],
    [" 30"],
    ["30 "],
  ])("rejects malformed MISP_TIMEOUT value %j", (value) => {
    process.env.MISP_TIMEOUT = value;
    expect(() => getConfig()).toThrow(/^MISP_TIMEOUT/);
  });

  it("rejects values above the documented maximum", () => {
    process.env.MISP_TIMEOUT = "3601";
    expect(() => getConfig()).toThrow(/^MISP_TIMEOUT/);
  });
});

describe("getConfig MISP_URL", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, ...REQUIRED_ENV };
    delete process.env.MISP_TIMEOUT;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it.each([
    ["https://misp.example.com", "https://misp.example.com"],
    ["https://misp.example.com/", "https://misp.example.com"],
    ["https://misp.example.com///", "https://misp.example.com"],
    ["https://misp.example.com:8443/misp/", "https://misp.example.com:8443/misp"],
    ["http://localhost:8080", "http://localhost:8080"],
    ["http://127.0.0.1", "http://127.0.0.1"],
    ["http://[::1]:8080/", "http://[::1]:8080"],
  ])("accepts %s", (input, expected) => {
    process.env.MISP_URL = input;
    expect(getConfig().url).toBe(expected);
  });

  it.each([
    ["http://misp.example.com", /must use https/],
    ["http://192.0.2.10", /must use https/],
    ["ftp://misp.example.com", /must use https/],
    ["file:///etc/passwd", /must use https/],
    ["javascript:alert(1)", /must use https/],
    ["https://user:secret@misp.example.com", /must not contain credentials/],
    ["https://user@misp.example.com", /must not contain credentials/],
    ["https://misp.example.com?token=abc", /query string or fragment/],
    ["https://misp.example.com/?", /query string or fragment/],
    ["https://misp.example.com/#frag", /query string or fragment/],
    ["misp.example.com", /absolute URL/],
    ["not a url", /absolute URL/],
  ])("rejects %s", (input, message) => {
    process.env.MISP_URL = input;
    expect(() => getConfig()).toThrow(message);
  });

  it("never echoes the rejected value", () => {
    process.env.MISP_URL = "https://user:hunter2@misp.example.com";
    expect(() => getConfig()).toThrow(/^(?!.*hunter2)/);
  });
});

describe("getConfig MISP_MAX_RESPONSE_BYTES", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, ...REQUIRED_ENV };
    delete process.env.MISP_MAX_RESPONSE_BYTES;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("defaults to 16 MiB", () => {
    expect(getConfig().maxResponseBytes).toBe(16 * 1024 * 1024);
  });

  it("accepts a value in range", () => {
    process.env.MISP_MAX_RESPONSE_BYTES = "2097152";
    expect(getConfig().maxResponseBytes).toBe(2_097_152);
  });

  it.each([["abc"], ["0"], ["-1"], ["1.5"], [""], ["1023"], ["268435457"]])(
    "rejects %j",
    (value) => {
      process.env.MISP_MAX_RESPONSE_BYTES = value;
      expect(() => getConfig()).toThrow(/^MISP_MAX_RESPONSE_BYTES/);
    }
  );
});
