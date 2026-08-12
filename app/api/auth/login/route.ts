import { NextRequest, NextResponse } from "next/server";
import { authenticate } from "@/lib/cinc/auth";
import { getConfig } from "@/lib/config";
import { getSession, shouldUseSecureCookies } from "@/lib/session";
import { log } from "@/lib/log";

export async function POST(req: NextRequest) {
  let body: { username?: string; password?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid request" }, { status: 400 });
  }
  const { username, password } = body;
  if (!username || !password) {
    return NextResponse.json({ error: "missing credentials" }, { status: 400 });
  }

  const { authMode } = getConfig();
  const authResult = await authenticate(username, password);
  if (!authResult) {
    log.warn("login.failed", { user: username, authMode });
    return NextResponse.json(
      { error: "invalid username or password" },
      { status: 401 },
    );
  }

  const session = await getSession();
  session.username = username;
  session.displayName = authResult.displayName || username;
  session.loginAt = Date.now();

  const secureCookie = await shouldUseSecureCookies();
  try {
    await session.save();
  } catch (err) {
    log.error("login.session-save-failed", { user: username, error: String(err) });
    return NextResponse.json(
      { error: "session creation failed" },
      { status: 500 },
    );
  }
  
  log.info("login.success", { user: username, authMode });

  // Next.js will attach cookies mutated during this request to the response.
  log.info("login.cookie-set", {
    user: username,
    cookieName: "cinc_console",
    secure: secureCookie,
  });
  return NextResponse.json({ ok: true });
}
