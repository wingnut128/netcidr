import { useState, useEffect } from "react";
import { Modal } from "./Modal";
import type { Supernet } from "../../../types";

interface AutoAllocateModalProps {
  open: boolean;
  onClose: () => void;
  supernets: Supernet[];
  defaultSupernetId?: string;
  onSubmit: (form: {
    supernetId: string;
    prefix: number;
    count: number;
    name: string;
    environment: string;
    owner: string;
  }) => Promise<void>;
}

export function AutoAllocateModal({
  open,
  onClose,
  supernets,
  defaultSupernetId,
  onSubmit,
}: AutoAllocateModalProps) {
  const [supernetId, setSupernetId] = useState("");
  const [prefix, setPrefix] = useState("24");
  const [count, setCount] = useState("1");
  const [name, setName] = useState("");
  const [environment, setEnvironment] = useState("");
  const [owner, setOwner] = useState("");

  useEffect(() => {
    if (open) {
      setSupernetId(defaultSupernetId ?? supernets[0]?.id ?? "");
      setPrefix("24");
      setCount("1");
      setName("");
      setEnvironment("");
      setOwner("");
    }
  }, [open, defaultSupernetId, supernets]);

  const handleSubmit = async () => {
    if (!supernetId || !prefix) return;
    await onSubmit({
      supernetId,
      prefix: Number(prefix),
      count: Number(count) || 1,
      name: name.trim(),
      environment: environment.trim(),
      owner: owner.trim(),
    });
  };

  return (
    <Modal open={open} onClose={onClose} title="Auto-Allocate">
      <div className="space-y-3">
        <div>
          <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
            Supernet
          </label>
          <select
            className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
            value={supernetId}
            onChange={(e) => setSupernetId(e.target.value)}
          >
            {supernets.map((sn) => (
              <option key={sn.id} value={sn.id}>
                {sn.cidr} {sn.name ? `– ${sn.name}` : ""}
              </option>
            ))}
          </select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
              Prefix Length
            </label>
            <input
              type="number"
              className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
              min={0}
              max={128}
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
              Count
            </label>
            <input
              type="number"
              className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
              min={1}
              value={count}
              onChange={(e) => setCount(e.target.value)}
            />
          </div>
        </div>
        <div>
          <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
            Name
          </label>
          <input
            type="text"
            className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
            placeholder="Optional"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
            Environment
          </label>
          <input
            type="text"
            className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
            placeholder="e.g. production"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          />
        </div>
        <div>
          <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
            Owner
          </label>
          <input
            type="text"
            className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
            placeholder="Optional"
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
          />
        </div>
        <button
          className="w-full font-mono text-[11px] font-bold uppercase tracking-[0.1em] px-4 py-2 border-2 border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
          onClick={handleSubmit}
        >
          ALLOCATE
        </button>
      </div>
    </Modal>
  );
}
