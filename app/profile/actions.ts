"use server";

import { getSession, requireUser } from "@/lib/session";
import { getUser, putUser } from "@/lib/cinc/users";
import { runAction, type ActionResult } from "@/lib/cinc/action";
import { getConfig } from "@/lib/config";

export type ProfileDetails = {
  display_name?: string;
  first_name?: string;
  last_name?: string;
  email?: string;
};

/**
 * The only fields this form may write. A Server Action is a public endpoint and
 * its parameter type is erased at runtime, so a caller can hand us any object it
 * likes — spreading that straight onto the user record would let it set fields
 * the UI never exposes (`password`, `public_key`, the recovery/external-auth
 * flags) on a request signed with the trusted webui key. Pick, don't spread.
 */
const PROFILE_FIELDS = [
  "display_name",
  "first_name",
  "last_name",
  "email",
] as const satisfies readonly (keyof ProfileDetails)[];

function pickProfileFields(details: ProfileDetails): ProfileDetails {
  const out: ProfileDetails = {};
  for (const field of PROFILE_FIELDS) {
    const value = details?.[field];
    if (typeof value === "string") out[field] = value;
  }
  return out;
}

/** Update the logged-in user's profile fields (PUT replaces, so merge first). */
export async function saveProfile(
  details: ProfileDetails,
): Promise<ActionResult> {
  const user = await requireUser();
  const allowed = pickProfileFields(details);
  const current = await getUser(user);
  const result = await runAction(() => putUser(user, { ...current, ...allowed }));
  // Keep the header's display name in sync after a successful change.
  if ("ok" in result && allowed.display_name !== undefined) {
    const session = await getSession();
    session.displayName = allowed.display_name || user;
    await session.save();
  }
  return result;
}

/** Change the logged-in user's web-login password. */
export async function changePassword(password: string): Promise<ActionResult> {
  const user = await requireUser();
  // LDAP-authenticated users have no Chef-side password to change — the
  // directory is authoritative. Guard the action itself (not just the UI)
  // in case it's ever invoked directly.
  if (getConfig().authMode === "ldap") {
    return { error: "password is managed by your organization's directory" };
  }
  // Same reasoning as pickProfileFields: the `string` annotation is not a runtime
  // check, and `(5).length < 6` is false — a non-string would sail past it.
  if (typeof password !== "string" || password.length < 6) {
    return { error: "password must be at least 6 characters" };
  }
  const current = await getUser(user);
  return runAction(() => putUser(user, { ...current, password }));
}
