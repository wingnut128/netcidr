import { useState } from "react";
import { useAuth } from "../../auth/AuthContext";

/**
 * Shown when a user is signed in via Google but their email is not on the
 * IPAM allowlist. Honest about the state of things — no fake "pending
 * approval" copy, no link to file a ticket. The admin's email is exposed
 * for direct contact.
 */
export function RequestAccessCard({ adminEmail }: { adminEmail?: string }) {
  const auth = useAuth();
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    if (!adminEmail) return;
    try {
      await navigator.clipboard.writeText(adminEmail);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard.writeText can reject in non-secure contexts; the email
      // is still visible in the UI for manual selection.
    }
  };

  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="bg-surface border border-border rounded-lg shadow-[0_1px_2px_rgba(15,23,42,0.04)] p-8 max-w-md w-full">
        <h2 className="text-text text-lg font-semibold mb-2">
          Access required
        </h2>
        <p className="text-text-muted text-sm mb-6 leading-relaxed">
          You're signed in as{" "}
          <span className="font-mono text-text">{auth.email}</span>, but
          this email is not on the IPAM allowlist. The administrator must
          add you before you can use the dashboard.
        </p>

        {adminEmail ? (
          <div className="mb-6">
            <p className="text-xs text-text-muted mb-1.5">
              Contact the administrator:
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 font-mono text-sm bg-bg border border-border rounded-md px-3 py-2 text-text truncate">
                {adminEmail}
              </code>
              <button
                type="button"
                onClick={() => void copy()}
                className="text-xs font-medium px-3 py-2 border border-border text-text-muted hover:border-cyan hover:text-cyan rounded-md cursor-pointer transition-colors"
              >
                {copied ? "COPIED" : "COPY"}
              </button>
            </div>
          </div>
        ) : (
          <p className="text-xs text-text-muted mb-6">
            No administrator email is configured. The deploy is missing
            <code className="font-mono mx-1">NETCIDR_ADMIN_EMAILS</code>.
          </p>
        )}

        <p className="text-xs text-text-muted mb-4 leading-relaxed">
          The other tools (Calc, Split, Contains, Summarize, Range) remain
          available without allowlist access.
        </p>

        <button
          type="button"
          onClick={() => auth.signOut()}
          className="text-xs font-medium px-4 py-2 border border-border text-text-muted hover:border-text hover:text-text rounded-md cursor-pointer transition-colors"
        >
          SIGN OUT
        </button>
      </div>
    </div>
  );
}
