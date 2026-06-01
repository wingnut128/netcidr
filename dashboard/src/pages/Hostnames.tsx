import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { AuthGate } from "../components/auth/AuthGate";
import { Modal } from "../components/ipam/modals/Modal";
import { TABLE_HEADER, FORM_LABEL, INPUT, BTN_PRIMARY } from "../lib/styles";
import { get, post, delVoid } from "../api";
import type {
  ChangeKind,
  CreateHostnamePointer,
  HostnamePointer,
  HostnamePointerList,
  HostnamePointerHistoryEntry,
  HostnamePointerHistoryList,
} from "../types";

function changeKindClass(kind: ChangeKind): string {
  switch (kind) {
    case "create":
      return "border-green/40 bg-green/10 text-green";
    case "delete":
      return "border-red/40 bg-red/10 text-red";
    default:
      return "border-cyan/40 bg-cyan/10 text-cyan";
  }
}

export function Hostnames() {
  return (
    <AuthGate>
      <HostnamesInner />
    </AuthGate>
  );
}

function HostnamesInner() {
  const [data, setData] = useState<HostnamePointerList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Filters
  const [filterIp, setFilterIp] = useState("");
  const [filterHost, setFilterHost] = useState("");

  // Set form
  const [ip, setIp] = useState("");
  const [hostname, setHostname] = useState("");
  const [notes, setNotes] = useState("");
  const [allocationId, setAllocationId] = useState("");

  // History modal
  const [history, setHistory] = useState<HostnamePointerHistoryEntry[] | null>(
    null,
  );
  const [historyTitle, setHistoryTitle] = useState("");

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (filterIp.trim()) params.set("ip", filterIp.trim());
    if (filterHost.trim()) params.set("hostname", filterHost.trim());
    const qs = params.toString();
    get<HostnamePointerList>(`/ipam/hostnames${qs ? `?${qs}` : ""}`)
      .then(setData)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
  }, [filterIp, filterHost]);

  useEffect(() => {
    load();
  }, [load]);

  const setPointer = async (e: React.FormEvent) => {
    e.preventDefault();
    const ipv = ip.trim();
    const hostv = hostname.trim();
    if (!ipv || !hostv) return;
    setBusy(true);
    setError(null);
    try {
      const body: CreateHostnamePointer = {
        ip_address: ipv,
        hostname: hostv,
        allocation_id: allocationId.trim() || undefined,
        notes: notes.trim() || undefined,
      };
      await post<HostnamePointer>("/ipam/hostnames", body);
      setIp("");
      setHostname("");
      setNotes("");
      setAllocationId("");
      load();
    } catch (err) {
      // Surfaces the backend's RequireAllocator 403 and validation errors.
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (p: HostnamePointer) => {
    setBusy(true);
    setError(null);
    try {
      await delVoid(
        `/ipam/hostnames?ip=${encodeURIComponent(p.ip_address)}&hostname=${encodeURIComponent(p.hostname)}`,
      );
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const showHistory = async (p: HostnamePointer) => {
    setError(null);
    try {
      const res = await get<HostnamePointerHistoryList>(
        `/ipam/hostnames/history?ip=${encodeURIComponent(p.ip_address)}`,
      );
      setHistoryTitle(`History — ${p.ip_address}`);
      setHistory(res.entries);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div>
      <PageHeader
        title="Hostnames"
        subtitle="Record which hostname(s) live at an IP, with a full append-only change history."
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Set a hostname pointer">
        <form
          onSubmit={setPointer}
          className="grid grid-cols-1 sm:grid-cols-2 gap-3"
        >
          <div>
            <label htmlFor="hp-ip" className={FORM_LABEL}>
              IP address
            </label>
            <input
              id="hp-ip"
              type="text"
              autoComplete="off"
              placeholder="10.0.1.5"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="hp-host" className={FORM_LABEL}>
              Hostname
            </label>
            <input
              id="hp-host"
              type="text"
              autoComplete="off"
              placeholder="web-01.example.com"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="hp-alloc" className={FORM_LABEL}>
              Allocation ID <span className="text-text-muted">(optional)</span>
            </label>
            <input
              id="hp-alloc"
              type="text"
              autoComplete="off"
              placeholder="(none)"
              value={allocationId}
              onChange={(e) => setAllocationId(e.target.value)}
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="hp-notes" className={FORM_LABEL}>
              Notes <span className="text-text-muted">(optional)</span>
            </label>
            <input
              id="hp-notes"
              type="text"
              autoComplete="off"
              placeholder="prod web"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className={INPUT}
            />
          </div>
          <div className="sm:col-span-2">
            <button type="submit" disabled={busy} className={BTN_PRIMARY}>
              {busy ? "Saving…" : "Set pointer"}
            </button>
          </div>
        </form>
        <p className="text-xs text-text-muted mt-3 leading-relaxed">
          An IP can carry several names, and a name can move between IPs over
          time. Setting an existing IP↔hostname pair updates its notes /
          allocation. Setting and deleting require the <span className="text-text">Allocator</span>{" "}
          role; every change is recorded in the pointer's history.
        </p>
      </Panel>

      <Panel title="Hostname pointers">
        <div className="flex flex-col sm:flex-row gap-2 mb-3">
          <input
            type="text"
            placeholder="Filter by IP"
            value={filterIp}
            onChange={(e) => setFilterIp(e.target.value)}
            className={INPUT}
          />
          <input
            type="text"
            placeholder="Filter by hostname"
            value={filterHost}
            onChange={(e) => setFilterHost(e.target.value)}
            className={INPUT}
          />
        </div>
        {!data ? (
          <p className="text-text-muted text-sm">Loading…</p>
        ) : data.pointers.length === 0 ? (
          <p className="text-text-muted text-sm">
            No hostname pointers{filterIp || filterHost ? " match the filter" : " yet"}.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className={TABLE_HEADER}>IP address</th>
                <th className={TABLE_HEADER}>Hostname</th>
                <th className={TABLE_HEADER}>Notes</th>
                <th className={TABLE_HEADER}>Updated</th>
                <th className={TABLE_HEADER}></th>
              </tr>
            </thead>
            <tbody>
              {data.pointers.map((p) => (
                <tr
                  key={p.id}
                  className="border-b border-border last:border-b-0 hover:bg-cyan/[0.03] transition-colors"
                >
                  <td className="px-3 py-2 font-mono">{p.ip_address}</td>
                  <td className="px-3 py-2 font-mono">{p.hostname}</td>
                  <td className="px-3 py-2 text-text-muted">
                    {p.notes ?? "—"}
                  </td>
                  <td className="px-3 py-2 text-text-muted font-mono tabular-nums">
                    {p.updated_at.slice(0, 10)}
                  </td>
                  <td className="px-3 py-2 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => showHistory(p)}
                      className="text-xs text-text-muted hover:text-cyan cursor-pointer mr-3"
                    >
                      History
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => remove(p)}
                      className="text-xs text-text-muted hover:text-red cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Modal
        open={history !== null}
        onClose={() => setHistory(null)}
        title={historyTitle}
      >
        {history && history.length === 0 ? (
          <p className="text-text-muted text-sm">No history recorded.</p>
        ) : (
          <ul className="space-y-3">
            {history?.map((h) => (
              <li key={h.id} className="text-sm border-b border-border pb-2 last:border-b-0">
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={`inline-block px-2 py-0.5 text-xs font-medium capitalize rounded-md border ${changeKindClass(h.change_kind)}`}
                  >
                    {h.change_kind}
                  </span>
                  <span className="font-mono">{h.hostname}</span>
                  <span className="text-text-muted text-xs ml-auto font-mono tabular-nums">
                    {h.changed_at.slice(0, 19).replace("T", " ")}
                  </span>
                </div>
                <p className="text-xs text-text-muted">
                  by <span className="font-mono">{h.actor}</span>
                </p>
              </li>
            ))}
          </ul>
        )}
      </Modal>
    </div>
  );
}
