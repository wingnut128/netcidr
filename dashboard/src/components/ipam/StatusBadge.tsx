import type { AllocationStatus } from "../../types";

const styles: Record<AllocationStatus, string> = {
  active: "border-green text-green",
  reserved: "border-yellow text-yellow",
  released: "border-text-muted text-text-muted",
};

export function StatusBadge({ status }: { status: AllocationStatus }) {
  return (
    <span
      className={`inline-block px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border-2 ${styles[status]}`}
    >
      {status}
    </span>
  );
}
