import type { ReactNode } from "react";

interface PanelProps {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function Panel({ title, actions, children, className = "" }: PanelProps) {
  return (
    <div className={`bg-surface border border-border ${className}`}>
      {(title || actions) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          {title && (
            <h2 className="text-text-muted text-xs uppercase tracking-widest font-bold">
              {title}
            </h2>
          )}
          {actions && <div className="flex gap-2">{actions}</div>}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}
