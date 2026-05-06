import type { TokenSummary } from "../../auth/tokens";
import { Modal } from "../ipam/modals/Modal";

interface RevokeTokenModalProps {
  token: TokenSummary | null;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void | Promise<void>;
}

export function RevokeTokenModal({
  token,
  busy,
  onCancel,
  onConfirm,
}: RevokeTokenModalProps) {
  if (!token) return null;

  return (
    <Modal open={true} onClose={onCancel} title="Revoke token">
      <p className="text-sm text-text mb-2">
        Revoke <span className="font-semibold">{token.name}</span>?
      </p>
      <p className="text-sm text-text-muted mb-4">
        Any client still using this token will fail authentication on its next
        request. This cannot be undone.
      </p>
      <div className="flex justify-end gap-2">
        <button
          type="button"
          className="px-4 py-2 text-sm text-text-muted hover:text-text"
          onClick={onCancel}
          disabled={busy}
        >
          Cancel
        </button>
        <button
          type="button"
          className="inline-flex items-center justify-center px-4 py-2 min-h-[44px] md:min-h-0 text-sm font-medium border border-red text-red rounded-md cursor-pointer hover:bg-red hover:text-bg transition-colors"
          onClick={() => void onConfirm()}
          disabled={busy}
        >
          {busy ? "Revoking..." : "Revoke"}
        </button>
      </div>
    </Modal>
  );
}
