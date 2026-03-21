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
    <div className={`bg-surface border border-border ${className}`}>
      {(title || actions) && (
        <div
          className={`flex items-center justify-between px-4 py-3 border-b border-border${collapsible ? " cursor-pointer select-none" : ""}`}
          onClick={collapsible ? () => setOpen((o) => !o) : undefined}
        >
          <div className="flex items-center gap-2">
            {collapsible && (
              <span
                className={`text-text-muted text-[10px] transition-transform duration-150${open ? " rotate-90" : ""}`}
              >
                ▶
              </span>
            )}
            {title && (
              <h2 className="text-text-muted text-xs uppercase tracking-widest font-bold">
                {title}
              </h2>
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
