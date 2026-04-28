import { useEffect, useState } from "react";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { AuthGate } from "../components/auth/AuthGate";
import { TABLE_HEADER } from "../lib/styles";
import { get } from "../api";

interface AllowlistResponse {
  emails: string[];
  admins: string[];
  /** "env" today; reserved for "db" once a mutable allowlist lands. */
  management: string;
}

export function AllowlistAdmin() {
  return (
    <AuthGate requireAdmin>
      <AllowlistAdminInner />
    </AuthGate>
  );
}

function AllowlistAdminInner() {
  const [data, setData] = useState<AllowlistResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    get<AllowlistResponse>("/admin/allowlist")
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div>
      <PageHeader
        title="Allowlist"
        subtitle="Email addresses authorized to use the IPAM dashboard."
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Allowlisted emails">
        {!data ? (
          <p className="text-text-muted text-sm">Loading…</p>
        ) : data.emails.length === 0 ? (
          <p className="text-text-muted text-sm">
            No emails allowlisted. Add one to get started — see the
            instructions panel below.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className={TABLE_HEADER}>Email</th>
                <th className={TABLE_HEADER}>Role</th>
              </tr>
            </thead>
            <tbody>
              {data.emails.map((email) => {
                const isAdmin = data.admins.some(
                  (a) => a.toLowerCase() === email.toLowerCase(),
                );
                return (
                  <tr
                    key={email}
                    className="border-b border-border last:border-b-0 hover:bg-cyan/[0.03] transition-colors"
                  >
                    <td className="px-3 py-2 font-mono">{email}</td>
                    <td className="px-3 py-2">
                      {isAdmin ? (
                        <span className="inline-block px-2 py-0.5 text-xs font-medium capitalize rounded-md border border-cyan/40 bg-cyan/10 text-cyan">
                          admin
                        </span>
                      ) : (
                        <span className="inline-block px-2 py-0.5 text-xs font-medium capitalize rounded-md border border-green/40 bg-green/10 text-green">
                          member
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="How to add or remove an email">
        <p className="text-sm text-text-muted leading-relaxed mb-3">
          The allowlist is currently sourced from the
          <code className="font-mono mx-1">NETCIDR_OIDC_ALLOWED_EMAILS</code>
          environment variable on the deployed Lambda. Changes require an
          update + redeploy.
        </p>
        <ol className="list-decimal list-inside text-sm text-text-muted space-y-1.5 leading-relaxed mb-3">
          <li>
            Edit
            <code className="font-mono mx-1">
              netcidr-deploy/aws/samconfig.toml.tpl
            </code>
            and append the email to
            <code className="font-mono mx-1">OidcAllowedEmails</code>
            (comma-separated).
          </li>
          <li>
            From
            <code className="font-mono mx-1">netcidr-deploy/aws/</code>
            run
            <code className="font-mono mx-1">
              op run --env-file=.env -- just deploy
            </code>
            to push the new env to Lambda.
          </li>
          <li>
            Refresh this page — the new email shows up in the table above.
          </li>
        </ol>
        <p className="text-xs text-text-muted">
          A database-backed mutable allowlist (with add/remove + audit) is
          on the roadmap. For now the source of truth is the env var.
        </p>
      </Panel>
    </div>
  );
}
