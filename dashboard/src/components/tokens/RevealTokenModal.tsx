import { useEffect, useState } from "react";
import type { CreateTokenResponse } from "../../auth/tokens";
import { BTN_PRIMARY } from "../../lib/styles";
import { Modal } from "../ipam/modals/Modal";
import { formatTokenDate } from "./tokenDisplay";

interface RevealTokenModalProps {
  token: CreateTokenResponse | null;
  onDismiss: () => void;
}

export function RevealTokenModal({
  token,
  onDismiss,
}: RevealTokenModalProps) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (token) setCopied(false);
  }, [token]);

  if (!token) return null;

  return (
    <Modal
      open={true}
      onClose={onDismiss}
      title="New token created"
      dismissible={false}
    >
      <p className="text-sm text-text-muted mb-3">
        Save this token now. You won&apos;t be able to see it again. If you lose
        it, revoke it and create a new one.
      </p>

      <div className="bg-bg border border-border rounded-md p-3 font-mono text-xs break-all select-all">
        {token.token}
      </div>

      <div className="mt-3 flex items-center gap-3">
        <button
          type="button"
          className="px-3 py-1.5 text-xs border border-border rounded-md text-text-muted hover:text-text"
          onClick={() => {
            void navigator.clipboard.writeText(token.token).then(() => {
              setCopied(true);
            });
          }}
        >
          {copied ? "Copied" : "Copy to clipboard"}
        </button>
        <span className="text-xs text-text-muted">
          Prefix <code className="font-mono">{token.prefix}</code> · role{" "}
          <span className="capitalize">{token.role}</span> · expires{" "}
          {formatTokenDate(token.expires_at)}
        </span>
      </div>

      <div className="mt-6 flex justify-end">
        <button type="button" className={BTN_PRIMARY} onClick={onDismiss}>
          I&apos;ve saved it
        </button>
      </div>
    </Modal>
  );
}
