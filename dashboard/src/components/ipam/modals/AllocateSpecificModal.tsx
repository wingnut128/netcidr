import { useState, useEffect } from "react";
import { Modal } from "./Modal";
import type { Supernet } from "../../../types";

interface AllocateSpecificModalProps {
  open: boolean;
  onClose: () => void;
  supernets: Supernet[];
  defaultSupernetId?: string;
  onSubmit: (form: {
    supernetId: string;
    cidr: string;
    name: string;
    environment: string;
    owner: string;
    resourceId: string;
  }) => Promise<void>;
}

export function AllocateSpecificModal({
  open,
  onClose,
  supernets,
  defaultSupernetId,
  onSubmit,
}: AllocateSpecificModalProps) {
  const [supernetId, setSupernetId] = useState("");
  const [cidr, setCidr] = useState("");
  const [name, setName] = useState("");
  const [environment, setEnvironment] = useState("");
  const [owner, setOwner] = useState("");
  const [resourceId, setResourceId] = useState("");

  useEffect(() => {
    if (open) {
      setSupernetId(defaultSupernetId ?? supernets[0]?.id ?? "");
      setCidr("");
      setName("");
      setEnvironment("");
      setOwner("");
      setResourceId("");
    }
  }, [open, defaultSupernetId, supernets]);

  const handleSubmit = async () => {
    if (!supernetId || !cidr.trim()) return;
    await onSubmit({
      supernetId,
      cidr: cidr.trim(),
      name: name.trim(),
      environment: environment.trim(),
      owner: owner.trim(),
      resourceId: resourceId.trim(),
    });
  };

  const field = (
    label: string,
    value: string,
    setter: (v: string) => void,
    placeholder: string,
  ) => (
    <div>
      <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
        {label}
      </label>
      <input
        type="text"
        className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
        placeholder={placeholder}
        value={value}
        onChange={(e) => setter(e.target.value)}
      />
    </div>
  );

  return (
    <Modal open={open} onClose={onClose} title="Allocate Specific">
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
        {field("CIDR", cidr, setCidr, "e.g. 10.0.1.0/24")}
        {field("Name", name, setName, "Optional")}
        {field("Environment", environment, setEnvironment, "e.g. production")}
        {field("Owner", owner, setOwner, "Optional")}
        {field("Resource ID", resourceId, setResourceId, "e.g. vpc-12345")}
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
