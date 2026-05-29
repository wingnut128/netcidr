import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { AuthGate } from "../components/auth/AuthGate";
import { useAuth } from "../auth/AuthContext";
import { TABLE_HEADER, FORM_LABEL, INPUT, BTN_PRIMARY } from "../lib/styles";
import { get, post, delVoid } from "../api";
import type { Role, RoleAssignment, RoleAssignmentList } from "../types";

const ROLES: Role[] = ["reader", "allocator", "admin"];

// Higher-privilege roles get warmer accents — mirrors the Reader<Allocator<Admin
// ordering in the backend `Role` enum.
function roleBadgeClass(role: Role): string {
  switch (role) {
    case "admin":
      return "border-cyan/40 bg-cyan/10 text-cyan";
    case "allocator":
      return "border-green/40 bg-green/10 text-green";
    default:
      return "border-border bg-surface2 text-text-muted";
  }
}

export function UsersAdmin() {
  return (
    <AuthGate requireAdmin>
      <UsersAdminInner />
    </AuthGate>
  );
}

function UsersAdminInner() {
  const auth = useAuth();
  const [data, setData] = useState<RoleAssignmentList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("reader");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    get<RoleAssignmentList>("/admin/users")
      .then(setData)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const grant = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = email.trim();
    if (!trimmed) return;
    setBusy(true);
    setError(null);
    try {
      await post<RoleAssignment>("/admin/users", { email: trimmed, role });
      setEmail("");
      setRole("reader");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (target: string) => {
    setBusy(true);
    setError(null);
    try {
      await delVoid(`/admin/users?email=${encodeURIComponent(target)}`);
      load();
    } catch (err) {
      // Surfaces backend guards (last-admin / self-revoke) inline.
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Users"
        subtitle="Grant and revoke role-based access by email. Roles are global; data stays tenant-isolated separately."
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Grant a role">
        <form
          onSubmit={grant}
          className="flex flex-col sm:flex-row sm:items-end gap-3"
        >
          <div className="flex-1">
            <label htmlFor="user-email" className={FORM_LABEL}>
              Email
            </label>
            <input
              id="user-email"
              type="email"
              autoComplete="off"
              placeholder="alice@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={INPUT}
            />
          </div>
          <div className="sm:w-44">
            <label htmlFor="user-role" className={FORM_LABEL}>
              Role
            </label>
            <select
              id="user-role"
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className={INPUT}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          <button type="submit" disabled={busy} className={BTN_PRIMARY}>
            {busy ? "Saving…" : "Grant"}
          </button>
        </form>
        <p className="text-xs text-text-muted mt-3 leading-relaxed">
          Granting an existing email updates its role. The last remaining admin
          cannot be revoked, and you cannot revoke your own admin role. Every
          change is recorded in the{" "}
          <span className="text-text">Activity</span> log.
        </p>
      </Panel>

      <Panel title="Role assignments">
        {!data ? (
          <p className="text-text-muted text-sm">Loading…</p>
        ) : data.users.length === 0 ? (
          <p className="text-text-muted text-sm">
            No role assignments yet. Grant one above to get started.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className={TABLE_HEADER}>Email</th>
                <th className={TABLE_HEADER}>Role</th>
                <th className={TABLE_HEADER}>Granted by</th>
                <th className={TABLE_HEADER}>Updated</th>
                <th className={TABLE_HEADER}></th>
              </tr>
            </thead>
            <tbody>
              {data.users.map((u) => {
                const isSelf =
                  auth.email != null &&
                  auth.email.toLowerCase() === u.email.toLowerCase();
                return (
                  <tr
                    key={u.email}
                    className="border-b border-border last:border-b-0 hover:bg-cyan/[0.03] transition-colors"
                  >
                    <td className="px-3 py-2 font-mono">
                      {u.email}
                      {isSelf && (
                        <span className="text-text-muted ml-1.5">(you)</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-block px-2 py-0.5 text-xs font-medium capitalize rounded-md border ${roleBadgeClass(
                          u.role,
                        )}`}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-text-muted">
                      {u.created_by ?? "—"}
                    </td>
                    <td className="px-3 py-2 text-text-muted font-mono tabular-nums">
                      {u.updated_at.slice(0, 10)}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => revoke(u.email)}
                        className="text-xs text-text-muted hover:text-red cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
