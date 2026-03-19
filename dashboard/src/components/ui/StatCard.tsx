interface StatCardProps {
  label: string;
  value: string | number;
  color?: "cyan" | "green" | "yellow" | "red" | "orange" | "purple";
  valueSize?: string;
}

const colorMap = {
  cyan: "text-cyan",
  green: "text-green",
  yellow: "text-yellow",
  red: "text-red",
  orange: "text-orange",
  purple: "text-purple",
} as const;

export function StatCard({
  label,
  value,
  color = "cyan",
  valueSize,
}: StatCardProps) {
  return (
    <div className="bg-surface border-2 border-border p-4">
      <div className="text-[10px] font-bold uppercase tracking-[0.15em] text-text-muted mb-1">
        {label}
      </div>
      <div
        className={`text-[28px] font-bold tabular-nums ${colorMap[color]}`}
        style={valueSize ? { fontSize: valueSize } : undefined}
      >
        {value}
      </div>
    </div>
  );
}
