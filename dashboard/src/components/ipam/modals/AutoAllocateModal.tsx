import { useState, useEffect } from "react";
import { Modal } from "./Modal";
import type { CidrBlock } from "../../../types";
import { getErrorMessage } from "../../../lib/errors";
import { FORM_LABEL, INPUT, BTN_PRIMARY } from "../../../lib/styles";

interface AutoAllocateModalProps {
  open: boolean;
  onClose: () => void;
  cidr_blocks: CidrBlock[];
  defaultCidrBlockId?: string;
  onSubmit: (form: {
    cidr_blockId: string;
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
  cidr_blocks,
  defaultCidrBlockId,
  onSubmit,
}: AutoAllocateModalProps) {
  const [cidr_blockId, setCidrBlockId] = useState("");
  const [prefix, setPrefix] = useState("24");
  const [count, setCount] = useState("1");
  const [name, setName] = useState("");
  const [environment, setEnvironment] = useState("");
  const [owner, setOwner] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setCidrBlockId(defaultCidrBlockId ?? cidr_blocks[0]?.id ?? "");
      setPrefix("24");
      setCount("1");
      setName("");
      setEnvironment("");
      setOwner("");
      setError(null);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- only reset when modal opens
  }, [open, defaultCidrBlockId]);

  const handleSubmit = async () => {
    if (!cidr_blockId || !prefix) return;
    setError(null);
    try {
      await onSubmit({
        cidr_blockId,
        prefix: Number(prefix),
        count: Number(count) || 1,
        name: name.trim(),
        environment: environment.trim(),
        owner: owner.trim(),
      });
    } catch (e) {
      setError(getErrorMessage(e, "Auto-allocate failed"));
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Auto-allocate">
      <div className="space-y-3">
        {error && (
          <div className="border border-red/40 bg-red/10 text-red rounded-md px-3 py-2 text-xs">
            {error}
          </div>
        )}
        <div>
          <label className={FORM_LABEL}>
            CidrBlock
          </label>
          <select
            className={INPUT}
            value={cidr_blockId}
            onChange={(e) => setCidrBlockId(e.target.value)}
          >
            {cidr_blocks.map((sn) => (
              <option key={sn.id} value={sn.id}>
                {sn.cidr} {sn.name ? `– ${sn.name}` : ""}
              </option>
            ))}
          </select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={FORM_LABEL}>
              Prefix Length
            </label>
            <input
              type="number"
              className={INPUT}
              min={0}
              max={128}
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
            />
          </div>
          <div>
            <label className={FORM_LABEL}>
              Count
            </label>
            <input
              type="number"
              className={INPUT}
              min={1}
              value={count}
              onChange={(e) => setCount(e.target.value)}
            />
          </div>
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
            Environment
          </label>
          <input
            type="text"
            className={INPUT}
            placeholder="e.g. production"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          />
        </div>
        <div>
          <label className={FORM_LABEL}>
            Owner
          </label>
          <input
            type="text"
            className={INPUT}
            placeholder="Optional"
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
          />
        </div>
        <button className={BTN_PRIMARY} onClick={handleSubmit}>
          ALLOCATE
        </button>
      </div>
    </Modal>
  );
}
