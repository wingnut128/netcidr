import {
  UserManager,
  WebStorageStateStore,
  type User,
} from "oidc-client-ts";

const clientId = import.meta.env.VITE_OAUTH_WEB_CLIENT_ID as
  | string
  | undefined;

// Origin used for redirect URIs. Google requires these be registered
// verbatim on the OAuth Web Client.
const origin =
  typeof window !== "undefined" ? window.location.origin : "";

export const isAuthConfigured = Boolean(clientId);

export const userManager: UserManager | null = clientId
  ? new UserManager({
      authority: "https://accounts.google.com",
      client_id: clientId,
      redirect_uri: `${origin}/auth/callback`,
      silent_redirect_uri: `${origin}/auth/silent-callback`,
      response_type: "id_token",
      scope: "openid email profile",
      userStore: new WebStorageStateStore({ store: window.localStorage }),
      automaticSilentRenew: true,
      // Google's OIDC discovery endpoint requires an explicit `nonce` for
      // implicit flow, which oidc-client-ts handles automatically.
      loadUserInfo: false,
    })
  : null;

let cachedUser: User | null = null;

if (userManager) {
  void userManager.getUser().then((u) => {
    cachedUser = u;
  });
  userManager.events.addUserLoaded((u) => {
    cachedUser = u;
  });
  userManager.events.addUserUnloaded(() => {
    cachedUser = null;
  });
  userManager.events.addSilentRenewError(() => {
    cachedUser = null;
  });
  userManager.events.addAccessTokenExpired(() => {
    cachedUser = null;
  });
}

/**
 * Returns the current ID token if the user is signed in and the token has
 * not expired, otherwise null. Synchronous: reads from the in-memory cache
 * populated by oidc-client-ts events. Used by the API client to attach a
 * Bearer header to outgoing requests without making the call sites async.
 */
export function getCurrentIdToken(): string | null {
  const u = cachedUser;
  if (!u || u.expired) return null;
  return u.id_token ?? null;
}
