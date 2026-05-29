import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { AuthGate } from "../components/auth/AuthGate";
import { TABLE_HEADER } from "../lib/styles";
import { get } from "../api";
import type { AuditEntry, AuditList } from "../types";

// The audit log records mutations. We bucket each action into a coarse class
// for the per-day summary. Admin-ish actions (roles, tokens, allowlist) are
// called out separately from ordinary IPAM writes.
function actionClass(action: string): "admin" | "write" {
  const a = action.toLowerCase();
  if (a.includes("role") || a.includes("token") || a.includes("allowlist")) {
    return "admin";
  }
  return "write";
}

function dayOf(timestamp: string): string {
  // RFC3339 → YYYY-MM-DD (fall back to the raw value if unparseable).
  const d = new Date(timestamp);
  return Number.isNaN(d.getTime())
    ? timestamp.slice(0, 10)
    : d.toISOString().slice(0, 10);
}

interface DayGroup {
  day: string;
  entries: AuditEntry[];
  writes: number;
  admin: number;
}

function groupByDay(entries: AuditEntry[]): DayGroup[] {
  const map = new Map<string, DayGroup>();
  for (const e of entries) {
    const day = dayOf(e.timestamp);
    let g = map.get(day);
    if (!g) {
      g = { day, entries: [], writes: 0, admin: 0 };
      map.set(day, g);
    }
    g.entries.push(e);
    if (actionClass(e.action) === "admin") g.admin += 1;
    else g.writes += 1;
  }
  // Most recent day first; entries already arrive newest-first from the API.
  return [...map.values()].sort((a, b) => (a.day < b.day ? 1 : -1));
}

export function Activity() {
  return (
    <AuthGate requireAdmin>
      <ActivityInner />
    </AuthGate>
  );
}

function ActivityInner() {
  const [groups, setGroups] = useState<DayGroup[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The email currently applied to the query.
  const [appliedEmail, setAppliedEmail] = useState<string>("");
  // The email in the input box (applied on submit).
  const [emailInput, setEmailInput] = useState<string>("");

  const load = useCallback((email: string) => {
    setGroups(null);
    const qs = new URLSearchParams({ limit: "500" });
    if (email.trim()) qs.set("caller_email", email.trim());
    get<AuditList>(`/ipam/audit?${qs.toString()}`)
      .then((d) => setGroups(groupByDay(d.entries)))
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
  }, []);

  useEffect(() => {
    load(appliedEmail);
  }, [load, appliedEmail]);

  const totalEntries = groups
    ? groups.reduce((n, g) => n + g.entries.length, 0)
    : 0;

  return (
    <div>
      <PageHeader
        title="Activity"
        subtitle="Recent audited mutations, grouped by day. Filter by user to see who changed what."
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Filter">
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setAppliedEmail(emailInput);
          }}
        >
          <input
            type="email"
            value={emailInput}
            onChange={(e) => setEmailInput(e.target.value)}
            placeholder="user@example.com"
            className="px-3 py-1.5 text-sm font-mono rounded-md border border-border bg-surface focus:border-cyan outline-none"
          />
          <button
            type="submit"
            className="px-3 py-1.5 text-sm rounded-md border border-cyan/40 bg-cyan/10 text-cyan hover:bg-cyan/20 transition-colors"
          >
            Apply
          </button>
          {appliedEmail && (
            <button
              type="button"
              onClick={() => {
                setEmailInput("");
                setAppliedEmail("");
              }}
              className="px-3 py-1.5 text-sm rounded-md border border-border text-text-muted hover:bg-cyan/[0.03] transition-colors"
            >
              Clear
            </button>
          )}
        </form>
        <p className="text-xs text-text-muted mt-2">
          The audit log captures mutations only. Reads are not recorded.
        </p>
      </Panel>

      <Panel
        title={
          appliedEmail
            ? `Activity for ${appliedEmail} (${totalEntries})`
            : `Recent activity (${totalEntries})`
        }
      >
        {!groups ? (
          <p className="text-text-muted text-sm">Loading…</p>
        ) : groups.length === 0 ? (
          <p className="text-text-muted text-sm">No activity recorded.</p>
        ) : (
          <div className="space-y-5">
            {groups.map((g) => (
              <div key={g.day}>
                <div className="flex items-center justify-between mb-1.5">
                  <h3 className="text-sm font-semibold">{g.day}</h3>
                  <span className="text-xs text-text-muted">
                    {g.writes} write{g.writes === 1 ? "" : "s"}
                    {g.admin > 0 && ` · ${g.admin} admin`}
                  </span>
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr>
                      <th className={TABLE_HEADER}>Time</th>
                      <th className={TABLE_HEADER}>Action</th>
                      <th className={TABLE_HEADER}>Entity</th>
                      <th className={TABLE_HEADER}>User</th>
                    </tr>
                  </thead>
                  <tbody>
                    {g.entries.map((e) => (
                      <tr
                        key={e.id}
                        className="border-b border-border last:border-b-0 hover:bg-cyan/[0.03] transition-colors"
                      >
                        <td className="px-3 py-2 font-mono text-xs text-text-muted">
                          {e.timestamp.slice(11, 19) || e.timestamp}
                        </td>
                        <td className="px-3 py-2 font-mono">{e.action}</td>
                        <td className="px-3 py-2 font-mono text-xs">
                          {e.entity_type}/{e.entity_id}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">
                          {e.caller_email ?? (e.pat_id ? "(pat)" : "—")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
