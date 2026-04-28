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

export type AuthStatus =
  | "loading"
  | "anonymous"
  | "authenticated"
  | "disabled";

interface AuthContextValue {
  status: AuthStatus;
  email: string | null;
  name: string | null;
  picture: string | null;
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
  const [error, setError] = useState<string | null>(null);

  // On mount: if we have a cached, non-expired token, mark authenticated.
  useEffect(() => {
    if (!isAuthConfigured) return;
    const token = getCurrentIdToken();
    if (token) {
      const c = decodeClaims(token);
      setClaims(c);
      setStatus(c ? "authenticated" : "anonymous");
    } else {
      setStatus("anonymous");
    }
  }, []);

  // Auto-expire: schedule a flip to anonymous when the current token's
  // exp passes. Keeps the UI honest without polling.
  useEffect(() => {
    if (!claims) return;
    const msUntilExpiry = claims.exp * 1000 - Date.now();
    if (msUntilExpiry <= 0) {
      setIdToken(null);
      setClaims(null);
      setStatus("anonymous");
      return;
    }
    const id = window.setTimeout(() => {
      setIdToken(null);
      setClaims(null);
      setStatus("anonymous");
    }, msUntilExpiry);
    return () => window.clearTimeout(id);
  }, [claims]);

  const acceptCredential = useCallback((jwt: string) => {
    const c = setIdToken(jwt);
    if (!c) {
      setError("Sign-in succeeded but the credential could not be parsed.");
      return;
    }
    setClaims(c);
    setStatus("authenticated");
    setError(null);
  }, []);

  const signOut = useCallback(() => {
    setIdToken(null);
    setClaims(null);
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
      error,
      acceptCredential,
      signOut,
      reportError,
      clearError,
    }),
    [status, claims, error, acceptCredential, signOut, reportError, clearError],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
