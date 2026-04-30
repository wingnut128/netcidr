import type { ReactNode } from "react";

interface DataRowProps {
  label: string;
  children: ReactNode;
}

export function DataRow({ label, children }: DataRowProps) {
  return (
    <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center py-2 gap-0.5 sm:gap-3 border-b border-border last:border-b-0">
      <span className="text-text-muted text-sm">{label}</span>
      <span className="text-text font-mono text-sm sm:text-right break-all">
        {children}
      </span>
    </div>
  );
}
