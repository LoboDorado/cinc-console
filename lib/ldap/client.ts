// Server-only LDAP client: search-then-bind credential verification.
//
// Never imported into a Client Component — a compromised bundle leaking the
// service-account bind password would be as bad as leaking the webui key.
import "server-only";
import { createClient, type Client, type SearchEntry } from "ldapjs";
import { getConfig } from "../config";

export type LdapBindResult = { dn: string };

export type LdapAuthErrorReason =
  | "invalid_credentials"
  | "user_not_found"
  | "ambiguous_user"
  | "connection_error";

/**
 * Thrown by ldapBind() for every failure mode. `.reason` lets callers (see
 * lib/cinc/auth.ts) log a bad password, an unprovisioned username, and a
 * broken/misconfigured directory as three distinct, greppable events instead
 * of collapsing them all into "login failed".
 */
export class LdapAuthError extends Error {
  constructor(
    public reason: LdapAuthErrorReason,
    message?: string,
  ) {
    super(message ?? reason);
    this.name = "LdapAuthError";
  }
}

/**
 * RFC 4515 filter-value escaping: the five bytes that are special inside an
 * LDAP search filter (`\`, `*`, `(`, `)`, NUL) become `\<hex>`. Apply this to
 * untrusted input (the submitted username) before it's substituted into the
 * configured filter template — never to the template itself — so a value
 * like `*)(uid=*` can't break out of the intended clause and turn into an
 * always-matching filter (classic LDAP injection).
 */
export function escapeLdapFilterValue(value: string): string {
  return value.replace(/[\\*()\u0000]/g, (c) => {
    switch (c) {
      case "\\":
        return "\\5c";
      case "*":
        return "\\2a";
      case "(":
        return "\\28";
      case ")":
        return "\\29";
      default:
        return "\\00"; // NUL
    }
  });
}

function bindPromise(client: Client, dn: string, password: string): Promise<void> {
  return new Promise((resolve, reject) => {
    client.bind(dn, password, (err) => (err ? reject(err) : resolve()));
  });
}

function searchOneDn(client: Client, baseDn: string, filter: string, timeLimitSec: number): Promise<string> {
  return new Promise((resolve, reject) => {
    client.search(
      baseDn,
      // sizeLimit: 2 is a cheap way to detect "more than one match" without
      // pulling back an unbounded result set — we only ever need to know
      // whether there's exactly one.
      { filter, scope: "sub", attributes: ["dn"], sizeLimit: 2, timeLimit: timeLimitSec },
      (err, res) => {
        if (err) return reject(err);
        const dns: string[] = [];
        res.on("searchEntry", (entry: SearchEntry) => {
          // @types/ldapjs declares objectName as `string | null`, but the
          // real @ldapjs/messages implementation always returns a DN
          // instance (its setter runs DN.fromString() on any string it's
          // given). Coerce explicitly — passing that object straight into a
          // later client.bind(dn, ...) throws deep inside the BER encoder
          // ("stringToWrite must be a string") instead of failing here.
          if (entry.objectName) dns.push(String(entry.objectName));
        });
        res.on("error", reject);
        res.on("end", () => {
          if (dns.length === 0) {
            reject(new LdapAuthError("user_not_found", `no LDAP entry matches filter ${filter}`));
          } else if (dns.length > 1) {
            reject(new LdapAuthError("ambiguous_user", `${dns.length} LDAP entries match filter ${filter}`));
          } else {
            resolve(dns[0]);
          }
        });
      },
    );
  });
}

/**
 * Search-then-bind: bind as the configured service account (or anonymously,
 * if none is configured), search for exactly one entry matching the escaped
 * filter, then rebind as that entry's DN with the submitted password.
 *
 * Returns the bound DN on success. Throws LdapAuthError on every failure —
 * the caller decides how to log/branch on `.reason`. Never returns null so a
 * caller can't accidentally treat "directory unreachable" the same as "bad
 * password" by pattern-matching a falsy return.
 */
export async function ldapBind(username: string, password: string): Promise<LdapBindResult> {
  const { ldap: cfg } = getConfig();
  if (!cfg) {
    throw new Error("ldapBind() called without AUTH_MODE=ldap configured");
  }

  const client = createClient({
    url: cfg.url,
    timeout: cfg.searchTimeoutMs,
    connectTimeout: cfg.searchTimeoutMs,
    tlsOptions: { rejectUnauthorized: !cfg.tlsNoVerify, ca: cfg.caCert },
  });

  // ldapjs emits async connection/socket errors as 'error' events on the
  // client itself, separate from operation callbacks. An EventEmitter with
  // no 'error' listener throws (and crashes the process) on such an event,
  // so we always attach one — the actual failure still surfaces through the
  // bind/search callbacks below, this just prevents an unhandled crash.
  client.on("error", () => {});

  try {
    try {
      await bindPromise(client, cfg.bindDn ?? "", cfg.bindPassword ?? "");
    } catch (e) {
      // A failure to bind the service account is always a configuration
      // problem, never the end user's fault.
      throw new LdapAuthError("connection_error", `service bind failed: ${(e as Error).message}`);
    }

    const filter = cfg.userFilter.replace("{{username}}", escapeLdapFilterValue(username));
    const timeLimitSec = Math.max(1, Math.ceil(cfg.searchTimeoutMs / 1000));
    let dn: string;
    try {
      dn = await searchOneDn(client, cfg.baseDn, filter, timeLimitSec);
    } catch (e) {
      if (e instanceof LdapAuthError) throw e;
      throw new LdapAuthError("connection_error", `LDAP search failed: ${(e as Error).message}`);
    }

    try {
      await bindPromise(client, dn, password);
    } catch (e) {
      const err = e as { name?: string; code?: number; message?: string };
      if (err.name === "InvalidCredentialsError" || err.code === 49) {
        throw new LdapAuthError("invalid_credentials", "bad LDAP password");
      }
      throw new LdapAuthError("connection_error", `rebind as ${dn} failed: ${err.message}`);
    }

    return { dn };
  } finally {
    // Never let a failed unbind mask the real result/error above.
    await new Promise<void>((resolve) => client.unbind(() => resolve())).catch(() => {});
  }
}
