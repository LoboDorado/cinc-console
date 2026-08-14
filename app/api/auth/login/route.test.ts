// @vitest-environment node
import { beforeEach, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
  getConfig: vi.fn(),
  session: { username: "", displayName: "", loginAt: 0, save: vi.fn() },
}));

vi.mock("@/lib/cinc/auth", () => ({ authenticate: mocks.authenticate }));
vi.mock("@/lib/config", () => ({ getConfig: mocks.getConfig }));
vi.mock("@/lib/session", () => ({
  getSession: async () => mocks.session,
  cookieSecure: () => true,
}));
vi.mock("@/lib/log", () => ({
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

import { NextRequest } from "next/server";
import { POST } from "./route";

function login(
  headers: Record<string, string>,
  body: unknown = { username: "anna", password: "anna123" },
): NextRequest {
  return new NextRequest("https://console.test/api/auth/login", {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const jsonHeaders = {
  host: "console.test",
  "content-type": "application/json",
  "sec-fetch-site": "same-origin",
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.getConfig.mockReturnValue({ authMode: "local" });
  mocks.authenticate.mockResolvedValue({ username: "anna", displayName: "Anna" });
});

test("the console's own login succeeds and seeds the session", async () => {
  const res = await POST(login(jsonHeaders));
  expect(res.status).toBe(200);
  expect(mocks.session.username).toBe("anna");
  expect(mocks.session.save).toHaveBeenCalled();
});

test("a cross-site login attempt is rejected before credentials are used", async () => {
  // Login CSRF: the attacker doesn't need the victim's cookie, only the
  // Set-Cookie in our response — so this has to fail without authenticating.
  const res = await POST(
    login({ ...jsonHeaders, origin: "https://evil.example", "sec-fetch-site": "cross-site" }),
  );
  expect(res.status).toBe(403);
  expect(mocks.authenticate).not.toHaveBeenCalled();
  expect(mocks.session.save).not.toHaveBeenCalled();
});

test("a text/plain body is refused (the no-preflight CSRF shape)", async () => {
  // `enctype="text/plain"` is how a cross-site form smuggles JSON past CORS;
  // Request.json() would happily parse it.
  const res = await POST(
    login(
      { host: "console.test", "content-type": "text/plain" },
      '{"username":"attacker","password":"pw"}',
    ),
  );
  expect(res.status).toBe(415);
  expect(mocks.authenticate).not.toHaveBeenCalled();
});

test("non-string credentials are rejected, not passed through", async () => {
  const res = await POST(login(jsonHeaders, { username: { toString: 1 }, password: 5 }));
  expect(res.status).toBe(400);
  expect(mocks.authenticate).not.toHaveBeenCalled();
});

test("bad credentials give 401 and no session", async () => {
  mocks.authenticate.mockResolvedValue(null);
  const res = await POST(login(jsonHeaders));
  expect(res.status).toBe(401);
  expect(mocks.session.save).not.toHaveBeenCalled();
});
