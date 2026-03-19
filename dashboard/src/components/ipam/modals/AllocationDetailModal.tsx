import { useState } from "react";
import { Modal } from "./Modal";
import { DataRow } from "../../ui/DataRow";
import { StatusBadge } from "../StatusBadge";
import { fmtDate, fmtNum } from "../../../lib/format";
import type { Allocation } from "../../../types";

interface AllocationDetailModalProps {
  open: boolean;
  onClose: () => void;
  allocation: Allocation | null;
  onAddTag: (
    allocationId: string,
    key: string,
    value: string,
  ) => Promise<void>;
}

export function AllocationDetailModal({
  open,
  onClose,
  allocation,
  onAddTag,
}: AllocationDetailModalProps) {
  const [tagKey, setTagKey] = useState("");
  const [tagValue, setTagValue] = useState("");

  if (!allocation) return null;

  const handleAddTag = async () => {
    const k = tagKey.trim();
    const v = tagValue.trim();
    if (!k || !v) return;
    await onAddTag(allocation.id, k, v);
    setTagKey("");
    setTagValue("");
  };

  return (
    <Modal open={open} onClose={onClose} title="Allocation Detail">
      <div className="space-y-1">
        <DataRow label="ID">
          <span className="text-[10px] text-text-muted">{allocation.id}</span>
        </DataRow>
        <DataRow label="CIDR">
          <span className="text-cyan">{allocation.cidr}</span>
        </DataRow>
        <DataRow label="Status">
          <StatusBadge status={allocation.status} />
        </DataRow>
        <DataRow label="Name">{allocation.name ?? "-"}</DataRow>
        <DataRow label="Owner">{allocation.owner ?? "-"}</DataRow>
        <DataRow label="Environment">{allocation.environment ?? "-"}</DataRow>
        <DataRow label="Resource ID">{allocation.resource_id ?? "-"}</DataRow>
        <DataRow label="Resource Type">
          {allocation.resource_type ?? "-"}
        </DataRow>
        <DataRow label="Network">{allocation.network_address}</DataRow>
        <DataRow label="Broadcast">
          {allocation.broadcast_address ?? "-"}
        </DataRow>
        <DataRow label="Total Hosts">{fmtNum(allocation.total_hosts)}</DataRow>
        <DataRow label="Created">{fmtDate(allocation.created_at)}</DataRow>
        {allocation.released_at && (
          <DataRow label="Released">{fmtDate(allocation.released_at)}</DataRow>
        )}
        {allocation.expires_at && (
          <DataRow label="Expires">{fmtDate(allocation.expires_at)}</DataRow>
        )}
      </div>

      {/* Tags */}
      <div className="mt-4 pt-4 border-t border-border">
        <p className="text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-2">
          Tags
        </p>
        <div className="flex flex-wrap gap-1 mb-3">
          {(allocation.tags ?? []).map((t) => (
            <span
              key={t.key + t.value}
              className="inline-block px-2 py-0.5 text-[10px] border border-border text-text-muted"
            >
              {t.key}={t.value}
            </span>
          ))}
          {(!allocation.tags || allocation.tags.length === 0) && (
            <span className="text-text-muted text-[11px]">No tags</span>
          )}
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            className="flex-1 font-mono text-[12px] px-2 py-1 bg-bg border border-border text-text outline-none focus:border-cyan"
            placeholder="key"
            value={tagKey}
            onChange={(e) => setTagKey(e.target.value)}
          />
          <input
            type="text"
            className="flex-1 font-mono text-[12px] px-2 py-1 bg-bg border border-border text-text outline-none focus:border-cyan"
            placeholder="value"
            value={tagValue}
            onChange={(e) => setTagValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAddTag()}
          />
          <button
            className="font-mono text-[10px] font-bold uppercase px-3 py-1 border border-cyan text-cyan hover:bg-cyan hover:text-bg transition-colors"
            onClick={handleAddTag}
          >
            ADD
          </button>
        </div>
      </div>
    </Modal>
  );
}
