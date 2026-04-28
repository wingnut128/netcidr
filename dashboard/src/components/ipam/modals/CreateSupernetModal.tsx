import { useState, useEffect } from "react";
import { Modal } from "./Modal";
import { getErrorMessage } from "../../../lib/errors";
import { FORM_LABEL, INPUT, BTN_PRIMARY } from "../../../lib/styles";

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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setCidr("");
      setName("");
      setDescription("");
      setError(null);
    }
  }, [open]);

  const handleSubmit = async () => {
    if (!cidr.trim()) return;
    setError(null);
    try {
      await onSubmit({ cidr: cidr.trim(), name: name.trim(), description: description.trim() });
    } catch (e) {
      setError(getErrorMessage(e, "Create failed"));
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Create Supernet">
      <div className="space-y-3">
        {error && (
          <div className="bg-red/10 border border-red text-red px-3 py-2 text-xs">
            {error}
          </div>
        )}
        <div>
          <label className={FORM_LABEL}>
            CIDR
          </label>
          <input
            type="text"
            className={INPUT}
            placeholder="e.g. 10.0.0.0/8"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
          />
        </div>
        <div>
          <label className={FORM_LABEL}>
            Name
          </label>
          <input
            type="text"
            className={INPUT}
            placeholder="Optional"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <label className={FORM_LABEL}>
            Description
          </label>
          <textarea
            className={`${INPUT} min-h-[60px] resize-y`}
            placeholder="Optional"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <button className={BTN_PRIMARY} onClick={handleSubmit}>
          CREATE
        </button>
      </div>
    </Modal>
  );
}
