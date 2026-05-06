import { StatCard } from "../ui/StatCard";

interface IpamStatsProps {
  cidr_blockCount: number;
  allocationCount: number;
  avgUtilization: string;
  freeBlockCount: number;
}

export function IpamStats({
  cidr_blockCount,
  allocationCount,
  avgUtilization,
  freeBlockCount,
}: IpamStatsProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
      <StatCard label="CIDR Blocks" value={cidr_blockCount} color="green" />
      <StatCard label="Allocations" value={allocationCount} color="yellow" />
      <StatCard label="Avg Utilization" value={avgUtilization} color="orange" />
      <StatCard label="Free Blocks" value={freeBlockCount} color="purple" />
    </div>
  );
}
