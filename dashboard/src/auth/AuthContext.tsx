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
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [status, setStatus] = useState<AuthStatus>(
    isAuthConfigured ? "loading" : "disabled",
  );

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
    if (!userManager) return;
    await userManager.signinRedirect();
  }, []);

  const signOut = useCallback(async () => {
    if (!userManager) return;
    await userManager.removeUser();
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      email: (user?.profile?.email as string | undefined) ?? null,
      signIn,
      signOut,
    }),
    [status, user, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
