// @vitest-environment node
import { EventEmitter } from "node:events";
import { expect, test, vi, beforeEach } from "vitest";

const getConfigMock = vi.fn();
vi.mock("../config", () => ({ getConfig: () => getConfigMock() }));

// A hand-rolled fake ldapjs client: bind()/search() resolve via queued
// scripted results so each test can drive exactly the sequence it wants
// (service bind, then search, then rebind) without a real directory.
type BindScript = { err?: { name?: string; code?: number; message?: string } };
// entries may be plain strings or DN-object-like values (anything with a
// toString()) — the real @ldapjs/messages SearchResultEntry always hands
// back a DN instance here, never a plain string, despite what
// @types/ldapjs claims.
type SearchScript = { err?: Error; entries?: Array<string | { toString(): string }>; endErr?: Error };

const bindScripts: BindScript[] = [];
const searchScripts: SearchScript[] = [];
const bindCalls: Array<{ dn: unknown; password: string }> = [];
const searchCalls: Array<{ baseDn: string; options: unknown }> = [];
let unbindCalls = 0;

function makeFakeClient() {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    bind(dn: unknown, password: string, cb: (err?: unknown) => void) {
      bindCalls.push({ dn, password });
      const script = bindScripts.shift() ?? {};
      queueMicrotask(() => cb(script.err));
    },
    search(baseDn: string, options: unknown, cb: (err: unknown, res: EventEmitter) => void) {
      searchCalls.push({ baseDn, options });
      const script = searchScripts.shift() ?? { entries: [] };
      const res = new EventEmitter();
      queueMicrotask(() => {
        if (script.err) return cb(script.err, res as never);
        cb(null, res);
        queueMicrotask(() => {
          for (const dn of script.entries ?? []) {
            res.emit("searchEntry", { objectName: dn });
          }
          if (script.endErr) res.emit("error", script.endErr);
          else res.emit("end", null);
        });
      });
    },
    unbind(cb?: () => void) {
      unbindCalls++;
      queueMicrotask(() => cb?.());
    },
  });
}

vi.mock("ldapjs", () => ({
  createClient: vi.fn(() => makeFakeClient()),
}));

import { ldapBind, escapeLdapFilterValue, LdapAuthError } from "./client";

const baseLdapConfig = {
  url: "ldaps://dc1.example.com:636",
  baseDn: "dc=example,dc=com",
  bindDn: "cn=svc,dc=example,dc=com",
  bindPassword: "svc-pw",
  userFilter: "(uid={{username}})",
  searchTimeoutMs: 5000,
  tlsNoVerify: false,
};

beforeEach(() => {
  bindScripts.length = 0;
  searchScripts.length = 0;
  bindCalls.length = 0;
  searchCalls.length = 0;
  unbindCalls = 0;
  getConfigMock.mockReturnValue({ ldap: baseLdapConfig });
});

test("escapeLdapFilterValue escapes the five RFC 4515 special bytes", () => {
  expect(escapeLdapFilterValue("a\\b*c(d)e\u0000f")).toBe("a\\5cb\\2ac\\28d\\29e\\00f");
});

test("escapeLdapFilterValue leaves ordinary and unicode text untouched", () => {
  expect(escapeLdapFilterValue("alice.o'brien")).toBe("alice.o'brien");
  expect(escapeLdapFilterValue("josé")).toBe("josé");
});

test("escapeLdapFilterValue neutralizes a filter-injection attempt", () => {
  // A naive template substitution of this value would turn "(uid=X)" into an
  // always-true filter; the escaped form keeps it as a single literal value.
  const malicious = "*)(uid=*";
  expect(escapeLdapFilterValue(malicious)).toBe("\\2a\\29\\28uid=\\2a");
});

test("ldapBind returns the found DN on success and unbinds", async () => {
  bindScripts.push({}, {}); // service bind, then rebind
  searchScripts.push({ entries: ["uid=alice,dc=example,dc=com"] });

  await expect(ldapBind("alice", "pw")).resolves.toEqual({
    dn: "uid=alice,dc=example,dc=com",
  });
  expect(unbindCalls).toBe(1);
  expect(bindCalls[0]).toEqual({ dn: "cn=svc,dc=example,dc=com", password: "svc-pw" });
  expect(bindCalls[1]).toEqual({ dn: "uid=alice,dc=example,dc=com", password: "pw" });
});

test("coerces a DN-object-like objectName to a plain string before rebinding", async () => {
  // Regression test: the real @ldapjs/messages SearchResultEntry always
  // returns a DN instance from `objectName`, never a plain string (the
  // @types/ldapjs declaration is wrong). Passing that object straight into
  // client.bind() throws deep inside ldapjs's BER encoder ("stringToWrite
  // must be a string") instead of failing cleanly here.
  const dnObject = {
    toString: () => "uid=alice,dc=example,dc=com",
  };
  bindScripts.push({}, {});
  searchScripts.push({ entries: [dnObject] });

  const result = await ldapBind("alice", "pw");

  expect(result).toEqual({ dn: "uid=alice,dc=example,dc=com" });
  expect(typeof bindCalls[1].dn).toBe("string");
  expect(bindCalls[1].dn).toBe("uid=alice,dc=example,dc=com");
});

test("escapes the username before it reaches the search filter", async () => {
  bindScripts.push({}, {});
  searchScripts.push({ entries: ["uid=x,dc=example,dc=com"] });

  await ldapBind("*)(uid=*", "pw");

  expect(searchCalls[0].options).toMatchObject({ filter: "(uid=\\2a\\29\\28uid=\\2a)" });
});

test("bad password on rebind -> invalid_credentials", async () => {
  bindScripts.push({}, { err: { name: "InvalidCredentialsError", code: 49 } });
  searchScripts.push({ entries: ["uid=alice,dc=example,dc=com"] });

  const err = await ldapBind("alice", "wrong").catch((e) => e);
  expect(err).toBeInstanceOf(LdapAuthError);
  expect((err as LdapAuthError).reason).toBe("invalid_credentials");
  expect(unbindCalls).toBe(1);
});

test("no matching entry -> user_not_found", async () => {
  bindScripts.push({});
  searchScripts.push({ entries: [] });

  const err = await ldapBind("ghost", "pw").catch((e) => e);
  expect(err).toBeInstanceOf(LdapAuthError);
  expect((err as LdapAuthError).reason).toBe("user_not_found");
});

test("ambiguous match (>1 entry) -> ambiguous_user, fails closed", async () => {
  bindScripts.push({});
  searchScripts.push({
    entries: ["uid=dup,ou=a,dc=example,dc=com", "uid=dup,ou=b,dc=example,dc=com"],
  });

  const err = await ldapBind("dup", "pw").catch((e) => e);
  expect(err).toBeInstanceOf(LdapAuthError);
  expect((err as LdapAuthError).reason).toBe("ambiguous_user");
});

test("search uses sizeLimit: 2 to cheaply detect ambiguity", async () => {
  bindScripts.push({}, {});
  searchScripts.push({ entries: ["uid=alice,dc=example,dc=com"] });

  await ldapBind("alice", "pw");

  expect(searchCalls[0].options).toMatchObject({ sizeLimit: 2 });
});

test("service bind failure -> connection_error, distinct from bad password", async () => {
  bindScripts.push({ err: { message: "ECONNREFUSED" } });

  const err = await ldapBind("alice", "pw").catch((e) => e);
  expect(err).toBeInstanceOf(LdapAuthError);
  expect((err as LdapAuthError).reason).toBe("connection_error");
  expect(unbindCalls).toBe(1);
});

test("search failure -> connection_error", async () => {
  bindScripts.push({});
  searchScripts.push({ err: new Error("ETIMEDOUT") });

  const err = await ldapBind("alice", "pw").catch((e) => e);
  expect(err).toBeInstanceOf(LdapAuthError);
  expect((err as LdapAuthError).reason).toBe("connection_error");
});

test("unbind is always attempted, even on the service-bind failure path", async () => {
  bindScripts.push({ err: { message: "down" } });

  await ldapBind("alice", "pw").catch((e) => e);

  expect(unbindCalls).toBe(1);
});

test("throws a plain Error when AUTH_MODE is not ldap", async () => {
  getConfigMock.mockReturnValue({ ldap: undefined });
  await expect(ldapBind("alice", "pw")).rejects.toThrow(/AUTH_MODE=ldap/);
});
