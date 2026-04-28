interface StatCardProps {
  label: string;
  value: string | number;
  color?: "cyan" | "green" | "yellow" | "red" | "orange" | "purple";
  valueSize?: string;
}

const dotColor = {
  cyan: "bg-cyan",
  green: "bg-green",
  yellow: "bg-yellow",
  red: "bg-red",
  orange: "bg-orange",
  purple: "bg-purple",
} as const;

export function StatCard({
  label,
  value,
  color = "cyan",
  valueSize,
}: StatCardProps) {
  return (
    <div className="bg-surface border border-border rounded-md p-4 shadow-[0_1px_2px_rgba(15,23,42,0.04)]">
      <div className="flex items-center gap-2 mb-2">
        <span
          aria-hidden
          className={`inline-block h-1.5 w-1.5 rounded-full ${dotColor[color]}`}
        />
        <span className="text-xs font-medium text-text-muted">{label}</span>
      </div>
      <div
        className="text-3xl font-semibold tabular-nums text-text font-mono"
        style={valueSize ? { fontSize: valueSize } : undefined}
      >
        {value}
      </div>
    </div>
  );
}
