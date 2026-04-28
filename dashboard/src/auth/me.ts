/**
 * Calls the /me endpoint to discover whether the current ID token is
 * accepted by the backend (passes both signature validation AND the email
 * allowlist) and whether the user has administrative access.
 *
 * Distinct from raw IPAM API calls: /me returns a 200 even when the user
 * is signed in but not allowlisted — the body's `is_allowlisted: false`
 * is how the frontend differentiates anonymous (no token) from
 * unallowlisted (valid token, email not on the allowlist).
 */

export interface MeResponse {
  email: string | null;
  is_allowlisted: boolean;
  is_admin: boolean;
  /** First configured admin email — used by RequestAccessCard. */
  admin_contact: string | null;
}

export async function fetchMe(idToken: string): Promise<MeResponse | null> {
  const res = await fetch("/me", {
    headers: { Authorization: `Bearer ${idToken}` },
  });
  if (res.status === 401) return null;
  if (!res.ok) {
    throw new Error(`/me returned ${res.status}`);
  }
  return (await res.json()) as MeResponse;
}
