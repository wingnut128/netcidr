import { useState, useEffect } from "react";
import { Modal } from "./Modal";

interface CreateSupernetModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (form: {
    cidr: string;
    name: string;
    description: string;
  }) => Promise<void>;
}

export function CreateSupernetModal({
  open,
  onClose,
  onSubmit,
}: CreateSupernetModalProps) {
  const [cidr, setCidr] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  useEffect(() => {
    if (open) {
      setCidr("");
      setName("");
      setDescription("");
    }
  }, [open]);

  const handleSubmit = async () => {
    if (!cidr.trim()) return;
    await onSubmit({ cidr: cidr.trim(), name: name.trim(), description: description.trim() });
  };

  return (
    <Modal open={open} onClose={onClose} title="Create Supernet">
      <div className="space-y-3">
        <div>
          <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
            CIDR
          </label>
          <input
            type="text"
            className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
            placeholder="e.g. 10.0.0.0/8"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
          />
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
            Description
          </label>
          <textarea
            className="w-full min-h-[60px] font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan resize-y"
            placeholder="Optional"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <button
          className="w-full font-mono text-[11px] font-bold uppercase tracking-[0.1em] px-4 py-2 border-2 border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
          onClick={handleSubmit}
        >
          CREATE
        </button>
      </div>
    </Modal>
  );
}
