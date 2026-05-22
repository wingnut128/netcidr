import { useEffect, useState } from "react";
import { type Role } from "../../auth/tokens";
import { BTN_PRIMARY, FORM_LABEL, INPUT } from "../../lib/styles";
import { Modal } from "../ipam/modals/Modal";

const EXPIRY_OPTIONS: { label: string; days: number }[] = [
  { label: "30 days", days: 30 },
  { label: "60 days", days: 60 },
  { label: "90 days (default)", days: 90 },
  { label: "180 days", days: 180 },
  { label: "365 days (max)", days: 365 },
];

// Mirrors the server-side ordering. Showing `admin` last keeps the
// narrower-than-default reader at the top so it's easy to pick for CI
// scripts — the most common reason to narrow a PAT.
const ROLE_OPTIONS: { label: string; value: Role }[] = [
  { label: "Reader (read-only)", value: "reader" },
  { label: "Allocator (read + allocate)", value: "allocator" },
  { label: "Admin (full access — default)", value: "admin" },
];

interface CreateTokenModalProps {
  open: boolean;
  busy: boolean;
  onClose: () => void;
  onSubmit: (
    name: string,
    expiresInDays: number,
    role: Role,
  ) => void | Promise<void>;
}

export function CreateTokenModal({
  open,
  busy,
  onClose,
  onSubmit,
}: CreateTokenModalProps) {
  const [name, setName] = useState("");
  const [days, setDays] = useState(90);
  // Default `admin` matches the server's pre-feature semantics: the
  // server clamps `min(caller_role, requested_role)` on every use, so
  // an admin-defaulted PAT effectively grants the caller's resolved
  // role unless they explicitly narrow it here.
  const [role, setRole] = useState<Role>("admin");

  useEffect(() => {
    if (open) {
      setName("");
      setDays(90);
      setRole("admin");
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
          void onSubmit(trimmed, days, role);
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

        <div className="mt-4">
          <label className={FORM_LABEL} htmlFor="token-role">
            Role
          </label>
          <select
            id="token-role"
            className={INPUT}
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            {ROLE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <p className="mt-1 text-xs text-text-muted">
            The server clamps to your own role at mint time — narrowing
            works, widening doesn't.
          </p>
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
