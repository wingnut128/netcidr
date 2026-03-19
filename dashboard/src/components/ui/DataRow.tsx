import type { ReactNode } from "react";

interface DataRowProps {
  label: string;
  children: ReactNode;
}

export function DataRow({ label, children }: DataRowProps) {
  return (
    <div className="flex justify-between py-1.5 border-b border-border">
      <span className="text-text-muted uppercase text-[11px] tracking-[0.05em]">
        {label}
      </span>
      <span className="text-text font-semibold text-right">{children}</span>
    </div>
  );
}
