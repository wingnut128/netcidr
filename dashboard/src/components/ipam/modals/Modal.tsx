import type { ReactNode } from "react";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}

export function Modal({ open, onClose, title, children }: ModalProps) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex sm:items-center justify-center bg-black/70"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-surface border border-border w-full sm:max-w-lg sm:mx-4 h-full sm:h-auto sm:max-h-[90vh] overflow-y-auto flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b-2 border-border bg-surface2 sticky top-0">
          <h3 className="text-xs font-medium text-text-muted">
            {title}
          </h3>
          <button
            className="text-text-muted hover:text-text text-lg leading-none min-h-[44px] min-w-[44px] flex items-center justify-center sm:min-h-0 sm:min-w-0"
            onClick={onClose}
            aria-label="Close"
          >
            &times;
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}
