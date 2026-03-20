import { useState } from "react";
import { Panel } from "../ui/Panel";
import { StatusBadge } from "./StatusBadge";
import type { Allocation } from "../../types";
import { TABLE_HEADER, FORM_LABEL, INPUT } from "../../lib/styles";

interface IpamSearchProps {
  onFindIp: (address: string) => Promise<void>;
  onFindResource: (resourceId: string) => Promise<void>;
  searchResults: Allocation[];
}

export function IpamSearch({
  onFindIp,
  onFindResource,
  searchResults,
}: IpamSearchProps) {
  const [ip, setIp] = useState("");
  const [resource, setResource] = useState("");

  return (
    <Panel title="Search">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label className={FORM_LABEL}>
            Find IP
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              className={`flex-1 ${INPUT}`}
              placeholder="e.g. 10.0.1.50"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onFindIp(ip.trim())}
            />
            <button
              className="font-mono text-[10px] font-bold uppercase px-3 py-1 border-2 border-cyan text-cyan hover:bg-cyan hover:text-bg transition-colors"
              onClick={() => onFindIp(ip.trim())}
            >
              FIND
            </button>
          </div>
        </div>
        <div>
          <label className={FORM_LABEL}>
            Find Resource
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              className={`flex-1 ${INPUT}`}
              placeholder="e.g. vpc-123"
              value={resource}
              onChange={(e) => setResource(e.target.value)}
              onKeyDown={(e) =>
                e.key === "Enter" && onFindResource(resource.trim())
              }
            />
            <button
              className="font-mono text-[10px] font-bold uppercase px-3 py-1 border-2 border-cyan text-cyan hover:bg-cyan hover:text-bg transition-colors"
              onClick={() => onFindResource(resource.trim())}
            >
              FIND
            </button>
          </div>
        </div>
      </div>

      {searchResults.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-2">
            Search Results ({searchResults.length})
          </p>
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr>
                {["CIDR", "Name", "Status", "Owner"].map((h) => (
                  <th key={h} className={TABLE_HEADER}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {searchResults.map((a) => (
                <tr key={a.id} className="hover:bg-cyan/[0.03]">
                  <td className="px-3 py-2 border-b border-border text-cyan">
                    {a.cidr}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {a.name ?? "-"}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {a.owner ?? "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
