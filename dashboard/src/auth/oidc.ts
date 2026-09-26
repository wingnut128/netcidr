/**
 * In-memory cache of the Google ID token. A page reload requires sign-in.
 *
 * The dashboard uses Google Identity Services (`@react-oauth/google`)
 * which returns a JWT credential directly from the user's Google sign-in.
 * That JWT is the OIDC `id_token` — the same shape the Lambda backend
 * already validates against `oauth_web_client_id` (RS256, JWKS at
 * Google's certs endpoint, audience = client ID).
 *
 * This module is the small shared piece between the React AuthContext
 * (which manages the lifecycle) and the API client (which needs to
 * synchronously read the current token to attach as a Bearer header).
 */

import { jwtDecode } from "jwt-decode";

const LEGACY_STORAGE_KEY = "netcidr.idToken";

export interface IdTokenClaims {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  aud?: string;
  exp: number;
  iat: number;
}

const clientId = import.meta.env.VITE_OAUTH_WEB_CLIENT_ID as
  | string
  | undefined;

export const isAuthConfigured = Boolean(clientId);
export const oauthClientId = clientId ?? "";

let cachedToken: string | null = null;

// Earlier versions persisted ID tokens. Remove that copy on load, never
// restoring it into memory or sending it to the API.
function removeLegacyToken(): void {
  try {
    window.localStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    // Storage may be disabled; auth still works in memory.
  }
}

removeLegacyToken();

export function setIdToken(token: string | null): IdTokenClaims | null {
  removeLegacyToken();
  if (!token) {
    cachedToken = null;
    return null;
  }
  try {
    const claims = jwtDecode<IdTokenClaims>(token);
    if (claims.exp * 1000 <= Date.now()) {
      cachedToken = null;
      return null;
    }
    cachedToken = token;
    return claims;
  } catch {
    cachedToken = null;
    return null;
  }
}

/** Synchronous read of the cached ID token. Used by api.ts. */
export function getCurrentIdToken(): string | null {
  if (!cachedToken) return null;
  // Cheap expiry check; the proper handoff is handled in AuthContext.
  try {
    const claims = jwtDecode<IdTokenClaims>(cachedToken);
    if (claims.exp * 1000 < Date.now()) {
      cachedToken = null;
      return null;
    }
    return cachedToken;
  } catch {
    cachedToken = null;
    return null;
  }
}

export function decodeClaims(token: string): IdTokenClaims | null {
  try {
    return jwtDecode<IdTokenClaims>(token);
  } catch {
    return null;
  }
}
