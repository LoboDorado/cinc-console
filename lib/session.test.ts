import { expect, test, vi } from "vitest";

vi.mock("./config", () => ({
  getConfig: () => ({ sessionSecret: "x".repeat(32), sessionTtlSeconds: 100 }),
}));

import { buildSessionOptions } from "./session";

test("session cookie is httpOnly, lax, and ttl-bound", () => {
  const o = buildSessionOptions();
  expect(o.cookieName).toBe("cinc_console");
  expect(o.ttl).toBe(100);
  expect(o.cookieOptions?.httpOnly).toBe(true);
  expect(o.cookieOptions?.sameSite).toBe("lax");
});

test("session cookie is insecure in dev, secure in production", () => {
  const originalEnv = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "development";
    expect(buildSessionOptions().cookieOptions?.secure).toBe(false);
    process.env.NODE_ENV = "production";
    expect(buildSessionOptions().cookieOptions?.secure).toBe(true);
  } finally {
    process.env.NODE_ENV = originalEnv;
  }
});

test("session cookie secure flag can be overridden per request", () => {
  expect(buildSessionOptions(false).cookieOptions?.secure).toBe(false);
  expect(buildSessionOptions(true).cookieOptions?.secure).toBe(true);
});
