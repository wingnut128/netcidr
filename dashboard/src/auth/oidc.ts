/**
 * In-memory + localStorage cache of the Google ID token.
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

const STORAGE_KEY = "netcidr.idToken";

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

/** Restore from localStorage on first read; returns null if expired or absent. */
function loadFromStorage(): string | null {
  try {
    const t = window.localStorage.getItem(STORAGE_KEY);
    if (!t) return null;
    const claims = jwtDecode<IdTokenClaims>(t);
    if (claims.exp * 1000 < Date.now()) {
      window.localStorage.removeItem(STORAGE_KEY);
      return null;
    }
    return t;
  } catch {
    window.localStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

cachedToken = loadFromStorage();

export function setIdToken(token: string | null): IdTokenClaims | null {
  cachedToken = token;
  if (token) {
    window.localStorage.setItem(STORAGE_KEY, token);
    try {
      return jwtDecode<IdTokenClaims>(token);
    } catch {
      return null;
    }
  }
  window.localStorage.removeItem(STORAGE_KEY);
  return null;
}

/** Synchronous read of the cached ID token. Used by api.ts. */
export function getCurrentIdToken(): string | null {
  if (!cachedToken) return null;
  // Cheap expiry check; the proper handoff is handled in AuthContext.
  try {
    const claims = jwtDecode<IdTokenClaims>(cachedToken);
    if (claims.exp * 1000 < Date.now()) {
      cachedToken = null;
      window.localStorage.removeItem(STORAGE_KEY);
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
