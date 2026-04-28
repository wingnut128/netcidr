import { useState, useEffect } from "react";
import { Modal } from "./Modal";
import type { Supernet } from "../../../types";
import { getErrorMessage } from "../../../lib/errors";
import { FORM_LABEL, INPUT, BTN_PRIMARY } from "../../../lib/styles";

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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setSupernetId(defaultSupernetId ?? supernets[0]?.id ?? "");
      setCidr("");
      setName("");
      setEnvironment("");
      setOwner("");
      setResourceId("");
      setError(null);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- only reset when modal opens
  }, [open, defaultSupernetId]);

  const handleSubmit = async () => {
    if (!supernetId || !cidr.trim()) return;
    setError(null);
    try {
      await onSubmit({
        supernetId,
        cidr: cidr.trim(),
        name: name.trim(),
        environment: environment.trim(),
        owner: owner.trim(),
        resourceId: resourceId.trim(),
      });
    } catch (e) {
      setError(getErrorMessage(e, "Allocation failed"));
    }
  };

  const field = (
    label: string,
    value: string,
    setter: (v: string) => void,
    placeholder: string,
  ) => (
    <div>
      <label className={FORM_LABEL}>{label}</label>
      <input
        type="text"
        className={INPUT}
        placeholder={placeholder}
        value={value}
        onChange={(e) => setter(e.target.value)}
      />
    </div>
  );

  return (
    <Modal open={open} onClose={onClose} title="Allocate Specific">
      <div className="space-y-3">
        {error && (
          <div className="bg-red/10 border border-red text-red px-3 py-2 text-xs">
            {error}
          </div>
        )}
        <div>
          <label className={FORM_LABEL}>Supernet</label>
          <select
            className={INPUT}
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
        <button className={BTN_PRIMARY} onClick={handleSubmit}>
          ALLOCATE
        </button>
      </div>
    </Modal>
  );
}
