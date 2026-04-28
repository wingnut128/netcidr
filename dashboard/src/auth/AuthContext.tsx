import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { User } from "oidc-client-ts";
import { isAuthConfigured, userManager } from "./oidc";

export type AuthStatus =
  | "loading"
  | "anonymous"
  | "authenticated"
  | "disabled";

interface AuthContextValue {
  status: AuthStatus;
  user: User | null;
  email: string | null;
  /** Most recent sign-in error, surfaced to the UI. */
  error: string | null;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [status, setStatus] = useState<AuthStatus>(
    isAuthConfigured ? "loading" : "disabled",
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const um = userManager;
    if (!um) return;
    let cancelled = false;

    void um.getUser().then((u) => {
      if (cancelled) return;
      if (u && !u.expired) {
        setUser(u);
        setStatus("authenticated");
      } else {
        setUser(null);
        setStatus("anonymous");
      }
    });

    const onLoaded = (u: User) => {
      setUser(u);
      setStatus("authenticated");
    };
    const onUnloaded = () => {
      setUser(null);
      setStatus("anonymous");
    };

    um.events.addUserLoaded(onLoaded);
    um.events.addUserUnloaded(onUnloaded);
    um.events.addSilentRenewError(onUnloaded);
    um.events.addAccessTokenExpired(onUnloaded);

    return () => {
      cancelled = true;
      um.events.removeUserLoaded(onLoaded);
      um.events.removeUserUnloaded(onUnloaded);
      um.events.removeSilentRenewError(onUnloaded);
      um.events.removeAccessTokenExpired(onUnloaded);
    };
  }, []);

  const signIn = useCallback(async () => {
    setError(null);
    if (!userManager) {
      const msg =
        "Sign-in not configured. The dashboard build was missing VITE_OAUTH_WEB_CLIENT_ID — rebuild with the env var set.";
      console.error("[auth]", msg);
      setError(msg);
      return;
    }
    console.info("[auth] signinRedirect invoked");
    try {
      await userManager.signinRedirect();
      // signinRedirect navigates the page away; if execution continues
      // past the await, something prevented the redirect.
      console.warn("[auth] signinRedirect returned without navigating");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[auth] signinRedirect failed:", e);
      setError(`Sign-in failed: ${msg}`);
    }
  }, []);

  const signOut = useCallback(async () => {
    setError(null);
    if (!userManager) return;
    try {
      await userManager.removeUser();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[auth] removeUser failed:", e);
      setError(`Sign-out failed: ${msg}`);
    }
  }, []);

  const clearError = useCallback(() => setError(null), []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      email: (user?.profile?.email as string | undefined) ?? null,
      error,
      signIn,
      signOut,
      clearError,
    }),
    [status, user, error, signIn, signOut, clearError],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
