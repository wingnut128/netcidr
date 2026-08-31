import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  decodeClaims,
  getCurrentIdToken,
  isAuthConfigured,
  setIdToken,
  type IdTokenClaims,
} from "./oidc";
import { fetchMe } from "./me";

/**
 * Auth lifecycle states.
 *
 * - `loading`        — checking cached credential / fetching /me.
 * - `anonymous`      — no token, or token expired.
 * - `unallowlisted`  — valid token, but email not on the backend's allowlist.
 * - `authenticated`  — token valid + email allowlisted; IPAM is reachable.
 * - `disabled`       — build was missing VITE_OAUTH_WEB_CLIENT_ID, sign-in
 *                       cannot be initiated. The UI should explain how to fix.
 */
export type AuthStatus =
  | "loading"
  | "anonymous"
  | "unallowlisted"
  | "authenticated"
  | "disabled";

export interface AuthContextValue {
  status: AuthStatus;
  email: string | null;
  name: string | null;
  picture: string | null;
  /** Role >= admin (tenant-space admin; platform admins also pass). */
  isAdmin: boolean;
  /** Role == platform_admin — gates the Users directory surfaces. */
  isPlatformAdmin: boolean;
  /** A platform admin's email — for RequestAccessCard. */
  adminContact: string | null;
  /** Most recent sign-in error, surfaced to the UI. */
  error: string | null;
  /** Called by the Google sign-in widget on success. */
  acceptCredential: (jwt: string) => void;
  signOut: () => void;
  reportError: (msg: string) => void;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [claims, setClaims] = useState<IdTokenClaims | null>(null);
  const [status, setStatus] = useState<AuthStatus>(
    isAuthConfigured ? "loading" : "disabled",
  );
  const [isAdmin, setIsAdmin] = useState(false);
  const [isPlatformAdmin, setIsPlatformAdmin] = useState(false);
  const [adminContact, setAdminContact] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  /**
   * Verify the current token against the backend by calling /me.
   * Side-effect: sets status to authenticated / unallowlisted / anonymous
   * depending on what /me returns. Runs on mount when there's a cached
   * token and after every successful sign-in.
   */
  const verifyWithBackend = useCallback(async (token: string) => {
    try {
      const me = await fetchMe(token);
      if (!me) {
        setIdToken(null);
        setClaims(null);
        setIsAdmin(false);
        setIsPlatformAdmin(false);
        setAdminContact(null);
        setStatus("anonymous");
        return;
      }
      setIsAdmin(me.is_admin);
      setIsPlatformAdmin(me.is_platform_admin);
      setAdminContact(me.admin_contact);
      setStatus(me.is_allowlisted ? "authenticated" : "unallowlisted");
    } catch {
      // Network error or non-200: fall back to "authenticated" so the
      // user can still see public surfaces. /ipam/* will 401/403 if
      // anything is actually broken — that surfaces as a separate error.
      setStatus("authenticated");
    }
  }, []);

  // On mount: hydrate from localStorage, then verify with backend.
  useEffect(() => {
    if (!isAuthConfigured) return;
    const token = getCurrentIdToken();
    if (!token) {
      setStatus("anonymous");
      return;
    }
    const c = decodeClaims(token);
    setClaims(c);
    if (!c) {
      setStatus("anonymous");
      return;
    }
    void verifyWithBackend(token);
  }, [verifyWithBackend]);

  // Auto-expire: when the JWT's `exp` passes, drop everything to anonymous.
  useEffect(() => {
    if (!claims) return;
    const msUntilExpiry = claims.exp * 1000 - Date.now();
    if (msUntilExpiry <= 0) {
      setIdToken(null);
      setClaims(null);
      setIsAdmin(false);
      setIsPlatformAdmin(false);
      setAdminContact(null);
      setStatus("anonymous");
      return;
    }
    const id = window.setTimeout(() => {
      setIdToken(null);
      setClaims(null);
      setIsAdmin(false);
      setIsPlatformAdmin(false);
      setAdminContact(null);
      setStatus("anonymous");
    }, msUntilExpiry);
    return () => window.clearTimeout(id);
  }, [claims]);

  const acceptCredential = useCallback(
    (jwt: string) => {
      const c = setIdToken(jwt);
      if (!c) {
        setError("Sign-in succeeded but the credential could not be parsed.");
        return;
      }
      setClaims(c);
      setError(null);
      setStatus("loading");
      void verifyWithBackend(jwt);
    },
    [verifyWithBackend],
  );

  const signOut = useCallback(() => {
    setIdToken(null);
    setClaims(null);
    setIsAdmin(false);
    setIsPlatformAdmin(false);
    setStatus("anonymous");
    setError(null);
  }, []);

  const reportError = useCallback((msg: string) => setError(msg), []);
  const clearError = useCallback(() => setError(null), []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      email: claims?.email ?? null,
      name: claims?.name ?? null,
      picture: claims?.picture ?? null,
      isAdmin,
      isPlatformAdmin,
      adminContact,
      error,
      acceptCredential,
      signOut,
      reportError,
      clearError,
    }),
    [
      status,
      claims,
      isAdmin,
      isPlatformAdmin,
      adminContact,
      error,
      acceptCredential,
      signOut,
      reportError,
      clearError,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
