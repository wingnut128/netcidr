import type { AllocationStatus } from "../../types";

const styles: Record<AllocationStatus, string> = {
  active: "border-green/40 text-green bg-green/10",
  reserved: "border-yellow/40 text-yellow bg-yellow/10",
  released: "border-border text-text-muted bg-surface2",
};

export function StatusBadge({ status }: { status: AllocationStatus }) {
  return (
    <span
      className={`inline-block px-2 py-0.5 text-xs font-medium capitalize rounded-md border ${styles[status]}`}
    >
      {status}
    </span>
  );
}
