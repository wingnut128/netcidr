/** Format a number with locale separators (e.g., 1,234,567). */
export function fmtNum(n: number | string): string {
  const num = Number(n);
  if (isNaN(num)) return String(n);
  return num.toLocaleString();
}

/** Format a number with compact suffix (e.g., 1.2K, 3.4M). */
export function fmtSize(n: number | string): string {
  const num = Number(n);
  if (isNaN(num)) return String(n);
  if (num >= 1e9) return (num / 1e9).toFixed(1) + "B";
  if (num >= 1e6) return (num / 1e6).toFixed(1) + "M";
  if (num >= 1e3) return (num / 1e3).toFixed(1) + "K";
  return String(num);
}
