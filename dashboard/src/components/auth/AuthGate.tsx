import type { ReactNode } from "react";
import { useAuth } from "../../auth/AuthContext";
import { SignInCard } from "./SignInCard";
import { RequestAccessCard } from "./RequestAccessCard";

interface AuthGateProps {
  /** Render this when the user is allowlisted. */
  children: ReactNode;
  /**
   * If true, also require admin role. When the user is allowlisted but
   * not admin, render the same RequestAccessCard rather than the
   * children — clearest signal that this surface is admin-only.
   */
  requireAdmin?: boolean;
}

/**
 * Wraps an IPAM-gated surface and routes by auth state:
 *   - loading        → spinner
 *   - anonymous      → SignInCard
 *   - disabled       → SignInCard (which shows the "not configured" path)
 *   - unallowlisted  → RequestAccessCard
 *   - authenticated, requireAdmin && !isAdmin → RequestAccessCard
 *   - authenticated, allowed → children
 */
export function AuthGate({ children, requireAdmin = false }: AuthGateProps) {
  const auth = useAuth();

  if (auth.status === "loading") {
    return (
      <div className="flex items-center justify-center min-h-[60vh] text-text-muted text-xs">
        Loading…
      </div>
    );
  }

  if (auth.status === "anonymous" || auth.status === "disabled") {
    return <SignInCard />;
  }

  if (auth.status === "unallowlisted") {
    return <RequestAccessCard adminEmail={auth.adminContact ?? undefined} />;
  }

  if (requireAdmin && !auth.isAdmin) {
    return <RequestAccessCard adminEmail={auth.adminContact ?? undefined} />;
  }

  return <>{children}</>;
}
