import type { ReactNode } from "react";

interface DataRowProps {
  label: string;
  children: ReactNode;
}

export function DataRow({ label, children }: DataRowProps) {
  return (
    <div className="flex justify-between items-center py-2 border-b border-border last:border-b-0">
      <span className="text-text-muted text-sm">{label}</span>
      <span className="text-text font-mono text-sm text-right">
        {children}
      </span>
    </div>
  );
}
