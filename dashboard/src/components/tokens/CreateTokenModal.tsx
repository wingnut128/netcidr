import { useEffect, useState } from "react";
import { BTN_PRIMARY, FORM_LABEL, INPUT } from "../../lib/styles";
import { Modal } from "../ipam/modals/Modal";

const EXPIRY_OPTIONS: { label: string; days: number }[] = [
  { label: "30 days", days: 30 },
  { label: "60 days", days: 60 },
  { label: "90 days (default)", days: 90 },
  { label: "180 days", days: 180 },
  { label: "365 days (max)", days: 365 },
];

interface CreateTokenModalProps {
  open: boolean;
  busy: boolean;
  onClose: () => void;
  onSubmit: (name: string, expiresInDays: number) => void | Promise<void>;
}

export function CreateTokenModal({
  open,
  busy,
  onClose,
  onSubmit,
}: CreateTokenModalProps) {
  const [name, setName] = useState("");
  const [days, setDays] = useState(90);

  useEffect(() => {
    if (open) {
      setName("");
      setDays(90);
    }
  }, [open]);

  const trimmed = name.trim();
  const valid = trimmed.length > 0 && trimmed.length <= 64;

  return (
    <Modal open={open} onClose={onClose} title="Create token">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid || busy) return;
          void onSubmit(trimmed, days);
        }}
      >
        <label className={FORM_LABEL} htmlFor="token-name">
          Name
        </label>
        <input
          id="token-name"
          className={INPUT}
          type="text"
          value={name}
          maxLength={64}
          autoFocus
          placeholder="e.g. ci-runner"
          onChange={(e) => setName(e.target.value)}
        />

        <div className="mt-4">
          <label className={FORM_LABEL} htmlFor="token-expiry">
            Expires in
          </label>
          <select
            id="token-expiry"
            className={INPUT}
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
          >
            {EXPIRY_OPTIONS.map((opt) => (
              <option key={opt.days} value={opt.days}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <div className="mt-6 flex justify-end gap-2">
          <button
            type="button"
            className="px-4 py-2 text-sm text-text-muted hover:text-text"
            onClick={onClose}
            disabled={busy}
          >
            Cancel
          </button>
          <button
            type="submit"
            className={BTN_PRIMARY}
            disabled={!valid || busy}
          >
            {busy ? "Creating..." : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
