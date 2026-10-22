import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseBooleanEnv } from "../src/env.js";
import { getConfig } from "../src/config.js";
import { destructiveEnvOptIn, requireConfirmation } from "../src/guards.js";
import { CliGateError, requireDestructiveCliGate } from "../src/cli-safety.js";

const TRUE_INPUTS = ["true", "TRUE", "True", " true ", "1", " 1\t"];
const FALSE_INPUTS = ["false", "FALSE", " False ", "0", " 0 "];
const DEFAULT_INPUTS = [undefined, "", "   "];
const INVALID_INPUTS = ["yes", "no", "on", "off", "2", "-1", "truee", "t", "enabled"];

describe("parseBooleanEnv", () => {
  it.each(TRUE_INPUTS)("parses %j as true", (raw) => {
    expect(parseBooleanEnv("X", raw, false)).toBe(true);
    expect(parseBooleanEnv("X", raw, true)).toBe(true);
  });

  it.each(FALSE_INPUTS)("parses %j as false", (raw) => {
    expect(parseBooleanEnv("X", raw, true)).toBe(false);
    expect(parseBooleanEnv("X", raw, false)).toBe(false);
  });

  it.each(DEFAULT_INPUTS)("returns the default for %j", (raw) => {
    expect(parseBooleanEnv("X", raw, true)).toBe(true);
    expect(parseBooleanEnv("X", raw, false)).toBe(false);
  });

  it.each(INVALID_INPUTS)("rejects %j and names the variable", (raw) => {
    expect(() => parseBooleanEnv("MISP_EXAMPLE", raw, false)).toThrow(/^MISP_EXAMPLE must be one of true, false, 1, or 0/);
  });
});

describe("MISP_VERIFY_SSL", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, MISP_URL: "https://misp.example.com", MISP_API_KEY: "k" };
    delete process.env.MISP_ALLOW_DESTRUCTIVE;
    delete process.env.MISP_VERIFY_SSL;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("keeps verification on by default", () => {
    expect(getConfig().verifySsl).toBe(true);
    process.env.MISP_VERIFY_SSL = "";
    expect(getConfig().verifySsl).toBe(true);
  });

  it.each(TRUE_INPUTS)("verifies for %j", (raw) => {
    process.env.MISP_VERIFY_SSL = raw;
    expect(getConfig().verifySsl).toBe(true);
  });

  it.each(FALSE_INPUTS)("disables verification for %j", (raw) => {
    process.env.MISP_VERIFY_SSL = raw;
    expect(getConfig().verifySsl).toBe(false);
  });

  it.each(INVALID_INPUTS)("refuses to start with MISP_VERIFY_SSL=%j", (raw) => {
    process.env.MISP_VERIFY_SSL = raw;
    expect(() => getConfig()).toThrow(/^MISP_VERIFY_SSL must be one of/);
  });

  it.each(INVALID_INPUTS)("refuses to start with MISP_ALLOW_DESTRUCTIVE=%j", (raw) => {
    process.env.MISP_ALLOW_DESTRUCTIVE = raw;
    expect(() => getConfig()).toThrow(/^MISP_ALLOW_DESTRUCTIVE must be one of/);
  });

  it.each(TRUE_INPUTS.concat(FALSE_INPUTS))("accepts MISP_ALLOW_DESTRUCTIVE=%j at startup", (raw) => {
    process.env.MISP_ALLOW_DESTRUCTIVE = raw;
    expect(() => getConfig()).not.toThrow();
  });
});

describe("MISP_ALLOW_DESTRUCTIVE agreement between the MCP guard and the CLI gate", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = originalEnv;
  });

  function cliAllows(env: NodeJS.ProcessEnv): boolean {
    try {
      requireDestructiveCliGate({ commandName: "test", env, confirm: true, destructive: true });
      return true;
    } catch (error) {
      if (error instanceof CliGateError) return false;
      throw error;
    }
  }

  function guardAllows(env: NodeJS.ProcessEnv): boolean {
    process.env = { ...originalEnv };
    if (env.MISP_ALLOW_DESTRUCTIVE === undefined) delete process.env.MISP_ALLOW_DESTRUCTIVE;
    else process.env.MISP_ALLOW_DESTRUCTIVE = env.MISP_ALLOW_DESTRUCTIVE;
    return requireConfirmation(undefined, "an action") === null;
  }

  it.each([...TRUE_INPUTS, ...FALSE_INPUTS, ...DEFAULT_INPUTS])("agree for %j", (raw) => {
    const env = { MISP_ALLOW_DESTRUCTIVE: raw } as NodeJS.ProcessEnv;
    expect(guardAllows(env)).toBe(cliAllows(env));
    expect(destructiveEnvOptIn(env)).toBe(cliAllows(env));
  });

  it.each(INVALID_INPUTS)("both fail closed for %j", (raw) => {
    const env = { MISP_ALLOW_DESTRUCTIVE: raw } as NodeJS.ProcessEnv;
    expect(() => cliAllows(env)).toThrow(/MISP_ALLOW_DESTRUCTIVE/);
    expect(() => guardAllows(env)).toThrow(/MISP_ALLOW_DESTRUCTIVE/);
  });

  it("treats 1, TRUE and ' true ' as enabled in both paths", () => {
    for (const raw of ["1", "TRUE", " true "]) {
      const env = { MISP_ALLOW_DESTRUCTIVE: raw } as NodeJS.ProcessEnv;
      expect(guardAllows(env)).toBe(true);
      expect(cliAllows(env)).toBe(true);
    }
  });
});
