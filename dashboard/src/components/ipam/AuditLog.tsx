import { Panel } from "../ui/Panel";
import { fmtDate } from "../../lib/format";
import type { AuditEntry } from "../../types";

export function AuditLog({ entries }: { entries: AuditEntry[] }) {
  return (
    <Panel title="Audit Log">
      {entries.length === 0 ? (
        <p className="text-text-muted text-center py-4">No audit entries.</p>
      ) : (
        <div className="space-y-1 max-h-64 overflow-y-auto">
          {entries.map((e) => (
            <div
              key={e.id}
              className="flex justify-between py-1 border-b border-border text-[11px]"
            >
              <span>
                <span className="text-cyan">{e.action}</span>{" "}
                <span className="text-text-muted">{e.entity_type}</span>{" "}
                {e.details && (
                  <span className="text-text-muted">{e.details}</span>
                )}
              </span>
              <span className="text-text-muted whitespace-nowrap ml-4">
                {fmtDate(e.timestamp)}
              </span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
