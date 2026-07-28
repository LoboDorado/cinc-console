import "server-only";
import { cookies, headers } from "next/headers";
import { getIronSession, type IronSession, type SessionOptions } from "iron-session";
import { getConfig } from "./config";

export type SessionData = {
  username?: string;
  displayName?: string;
  loginAt?: number;
};

export function buildSessionOptions(isSecure: boolean = process.env.NODE_ENV === "production"): SessionOptions {
  const cfg = getConfig();

  return {
    password: cfg.sessionSecret,
    cookieName: "cinc_console",
    ttl: cfg.sessionTtlSeconds,
    cookieOptions: {
      httpOnly: true,
      secure: isSecure,
      sameSite: "lax",
      path: "/",
    },
  };
}

/**
 * Determine whether the current request should receive a Secure session cookie.
 * In production we honor reverse-proxy proto headers when present.
 */
export async function shouldUseSecureCookies(): Promise<boolean> {
  if (process.env.NODE_ENV !== "production") return false;

  const h = await headers();
  const forwardedProto = h
    .get("x-forwarded-proto")
    ?.split(",")[0]
    ?.trim()
    .toLowerCase();
  if (forwardedProto) return forwardedProto === "https";

  const forwardedSsl = h.get("x-forwarded-ssl")?.trim().toLowerCase();
  if (forwardedSsl) return forwardedSsl === "on";

  const originLike = h.get("origin") ?? h.get("referer");
  if (originLike) {
    try {
      return new URL(originLike).protocol === "https:";
    } catch {
      // Ignore parse failures and fall through to the safe default.
    }
  }

  // No forwarding hints available: default to secure in production.
  return true;
}

export async function getSession(): Promise<IronSession<SessionData>> {
  // Built lazily (not at module load) so `next build` doesn't require runtime
  // config to be present when route modules are imported.
  const secure = await shouldUseSecureCookies();
  return getIronSession<SessionData>(await cookies(), buildSessionOptions(secure));
}

export class Unauthorized extends Error {
  constructor() {
    super("not authenticated");
    this.name = "Unauthorized";
  }
}

/** Returns the logged-in username or throws Unauthorized. */
export async function requireUser(): Promise<string> {
  const s = await getSession();
  if (!s.username) throw new Unauthorized();
  return s.username;
}
