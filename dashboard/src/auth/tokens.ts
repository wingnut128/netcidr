/**
 * Personal access token management — `/me/tokens` REST endpoints.
 *
 * The server gates this router as OIDC-only (see `src/me_api.rs::require_oidc`),
 * so all calls go through the standard `api.ts` client which attaches the OIDC
 * ID token from `auth/oidc.ts`. Re-using `api.ts` means responses already get
 * `ApiError` parsing on non-2xx.
 */

import { delVoid, get, post } from "../api";

export interface TokenSummary {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface TokenListResponse {
  tokens: TokenSummary[];
  count: number;
}

/** One-time mint result. `token` is the plaintext secret — show ONCE. */
export interface CreateTokenResponse {
  id: string;
  name: string;
  prefix: string;
  token: string;
  created_at: string;
  expires_at: string;
}

export interface CreateTokenRequest {
  name: string;
  expires_in_days?: number;
}

export function listTokens(): Promise<TokenListResponse> {
  return get<TokenListResponse>("/me/tokens");
}

export function createToken(
  req: CreateTokenRequest,
): Promise<CreateTokenResponse> {
  return post<CreateTokenResponse>("/me/tokens", req);
}

export async function revokeToken(id: string): Promise<void> {
  return delVoid(`/me/tokens/${encodeURIComponent(id)}`);
}
