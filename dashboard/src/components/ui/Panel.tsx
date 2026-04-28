import { type ReactNode, useState } from "react";

interface PanelProps {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  collapsible?: boolean;
  defaultOpen?: boolean;
}

export function Panel({
  title,
  actions,
  children,
  className = "",
  collapsible = false,
  defaultOpen = true,
}: PanelProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div
      className={`bg-surface border border-border rounded-md shadow-[0_1px_2px_rgba(15,23,42,0.04)] mb-4 ${className}`}
    >
      {(title || actions) && (
        <div
          className={`flex items-center justify-between px-4 py-3 border-b border-border${collapsible ? " cursor-pointer select-none" : ""}`}
          onClick={collapsible ? () => setOpen((o) => !o) : undefined}
        >
          <div className="flex items-center gap-2">
            {collapsible && (
              <svg
                aria-hidden
                viewBox="0 0 20 20"
                fill="currentColor"
                className={`h-4 w-4 text-text-muted transition-transform duration-150${open ? " rotate-90" : ""}`}
              >
                <path
                  fillRule="evenodd"
                  d="M7.05 4.05a.75.75 0 011.06 0l5.5 5.5a.75.75 0 010 1.06l-5.5 5.5a.75.75 0 01-1.06-1.06l4.97-4.97-4.97-4.97a.75.75 0 010-1.06z"
                  clipRule="evenodd"
                />
              </svg>
            )}
            {title && (
              <h2 className="text-text text-sm font-semibold">{title}</h2>
            )}
          </div>
          {actions && (
            <div
              className="flex gap-2"
              onClick={collapsible ? (e) => e.stopPropagation() : undefined}
            >
              {actions}
            </div>
          )}
        </div>
      )}
      {(!collapsible || open) && <div className="p-4">{children}</div>}
    </div>
  );
}
